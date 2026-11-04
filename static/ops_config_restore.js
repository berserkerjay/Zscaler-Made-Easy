/* Backups, restore and clone on Bulk changes (/report/operations, "Backups").
   The form of the three restore types (ops_config_restore.py: ZIA, ZPA,
   Client Connector) and the backup tools around them (config_backup.py):
   save a backup, keep a snapshot as one, compare two backups or a backup
   and the live tenant field by field, schedule backups, refresh the
   configuration cache, make and import templates, and rehearse a plan
   against the sample tenant or a saved copy. The page does the rest of a
   restore: Preview (plan hash), the four gates, Apply, read-back, Undo.
   A typed pre-shared key goes only into the apply's `secrets`, never into
   the operation, and is cleared from the form after the apply.
   Tenant-bound types (static IPs, GRE tunnels, locations, sub-locations) are
   listed apart and sent only with "Include tenant-bound objects" ticked; the
   Client Connector app profiles and entitlements clone only with "Include
   Client Connector app profiles and entitlements" ticked (never a password). */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;
  const PRODUCT = { config_restore_zia: 'zia', config_restore_zpa: 'zpa', config_restore_zcc: 'zcc' };
  const KIND = { manual: 'saved by hand', scheduled: 'scheduled', 'pre-restore': 'before a restore', snapshot: 'from a snapshot', sample: 'sample tenant' };

  function st(S) {
    if (!S.cfg) S.cfg = { from: 'backup', backup: '', template: '', target: 'same', mode: 'update_matching', types: null, keep: false, activate: true,
      ack: false, rollback: false, tb: false, zccp: false, prefix: '', psk: {}, keys: {}, diffOld: '', diffNew: 'live', ignore: '', tplType: '', tplNames: '', tplName: '',
      tplStrip: '', rehearse: 'sample' };
    return S.cfg;
  }
  function errs(H, res) {
    const rows = Object.entries((res && res.errors) || {});
    return rows.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${rows.map(([k, v]) => `<li>${H.E(k)}: ${H.E(v)}</li>`).join('')}</ul></div>` : '';
  }
  const when = v => String(v || '').replace('T', ' ').slice(0, 16);
  function writable(res, product) { return (((res.coverage || {}).products || {})[product] || []).filter(t => t.level !== 'read'); }

  function backupsTable(H, res, z) {
    const E = H.E, rows = res.backups || [];
    if (!rows.length) return '<div class="df-hint">No backup is saved yet. Save one below, or keep a snapshot (or the sample tenant) as one.</div>';
    return `<div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">Saved configuration backups</caption>
      <thead><tr><th scope="col">Use</th><th scope="col">Saved</th><th scope="col">Tenant</th><th scope="col">Kind</th><th scope="col">Objects</th><th scope="col">Files</th></tr></thead>
      <tbody>${rows.map(b => `<tr><td><input type="radio" name="crBackup" value="${E(b.id)}" aria-label="Restore from the backup of ${E(b.tenant_label)} saved ${E(when(b.saved_at))}"${z.backup === b.id ? ' checked' : ''}></td>
        <td>${E(when(b.saved_at))}</td><td>${E(b.tenant_label)}<div class="df-by">${E((b.products || []).join(', ').toUpperCase())}</div></td>
        <td>${E(KIND[b.kind] || b.kind)}${b.unread ? ` <span class="df-chip st-warn">${E(b.unread)} not read</span>` : ''}</td><td>${E(b.objects)}</td>
        <td><a class="rp-btn" href="/api/config-backups/${encodeURIComponent(b.id)}/download" download aria-label="Download the backup of ${E(b.tenant_label)} saved ${E(when(b.saved_at))}">Download</a>
          <button type="button" class="rp-btn" data-crdel="${E(b.id)}" aria-label="Delete the backup of ${E(b.tenant_label)} saved ${E(when(b.saved_at))}">Delete</button></td></tr>`).join('')}</tbody></table></div>`;
  }

  function render(res, where, S, H) {
    const E = H.E, z = st(S), product = PRODUCT[S.kind], all = writable(res, product);
    const types = all.filter(t => !t.tenant_bound), bound = all.filter(t => t.tenant_bound);
    S.cfgBound = new Set(bound.map(t => t.key));
    if (z.types === null) z.types = new Set(all.map(t => t.key));
    const typeBox = t => `<li><label><input type="checkbox" data-crtype="${E(t.key)}"${z.types.has(t.key) ? ' checked' : ''}> ${E(t.label)}</label>${t.why ? ` <span class="df-hint">${E(t.why)}</span>` : ''}</li>`;
    const tpls = res.templates || [];
    const psk = (types.find(t => t.key === 'zia.vpn_credentials') && product === 'zia');
    const singles = types.filter(t => t.singleton);
    const sideOpts = sel => `<option value="live"${sel === 'live' ? ' selected' : ''}>The live tenant (read now)</option>${(res.backups || []).map(b => `<option value="${E(b.id)}"${sel === b.id ? ' selected' : ''}>${E(when(b.saved_at))} · ${E(b.tenant_label)}</option>`).join('')}`;
    where.innerHTML = `${errs(H, res)}
      <p>Restore this tenant from one of its backups, clone another tenant's backup into it, or apply a template. The preview lists every object to create, update or delete, in dependency order, with what cannot be cloned and why. Nothing is written until you apply; a fresh backup of this tenant is saved first, and Undo puts back what was applied.</p>
      <h3 class="op-h">1. Source</h3>
      <div class="op-row"><fieldset class="op-inline"><legend>Restore from</legend>
        <label><input type="radio" name="crSrc" value="backup"${z.from === 'backup' ? ' checked' : ''}> A backup</label>
        <label><input type="radio" name="crSrc" value="template"${z.from === 'template' ? ' checked' : ''}> A template</label></fieldset></div>
      ${z.from === 'backup' ? backupsTable(H, res, z) : `<div class="op-row"><label class="df-ctl"><span class="lbl">Template</span><select id="crTemplate" aria-label="Template to apply">
          <option value="">Pick a template…</option>${tpls.map(t => `<option value="${E(t.id)}"${z.template === t.id ? ' selected' : ''}>${E(t.name)} (${E(t.objects)} objects)</option>`).join('')}</select></label>
        <label class="df-ctl"><span class="lbl">Prefix for the template's names</span><input id="crPrefix" value="${E(z.prefix)}" maxlength="20" autocomplete="off" aria-label="Prefix for the template's names" placeholder="ACME-"></label></div>`}
      <h3 class="op-h">2. Target</h3>
      <div class="op-row"><fieldset class="op-inline"><legend>This tenant is</legend>
        <label><input type="radio" name="crTarget" value="same"${z.target === 'same' ? ' checked' : ''}${z.from === 'template' ? ' disabled' : ''}> The backup's own tenant (restore)</label>
        <label><input type="radio" name="crTarget" value="other"${z.target === 'other' || z.from === 'template' ? ' checked' : ''}> Another tenant (clone)</label></fieldset></div>
      <div class="df-hint">A clone or template writes only to the tenant of the saved profile picked in the Tenant list above.</div>
      <h3 class="op-h">3. Mode and object types</h3>
      <div class="op-row"><fieldset class="op-inline"><legend>Mode</legend>${(res.modes || []).map(m => `<label><input type="radio" name="crMode" value="${E(m.id)}"${z.mode === m.id ? ' checked' : ''}${m.id === 'full' && z.from === 'template' ? ' disabled' : ''}> ${E(m.label)}</label>`).join(' ')}</fieldset></div>
      <ul class="op-checks">${types.map(typeBox).join('') || '<li class="df-hint">Nothing of this product is in scope.</li>'}</ul>
      ${bound.length ? `<div class="op-row"><label class="df-ctl"><input type="checkbox" id="crTb"${z.tb ? ' checked' : ''}><span>Include tenant-bound objects (static IP addresses, GRE tunnels, locations and their sub-locations)</span></label></div>
        <div class="df-hint">Off by default. When ticked, each static IP address is checked with this tenant first, sub-locations come after their parent location, nothing tenant-bound is ever updated or deleted, and the apply asks you to type CREATE n TENANT-BOUND OBJECTS.</div>
        ${z.tb ? `<ul class="op-checks" id="crTbTypes">${bound.map(typeBox).join('')}</ul>` : ''}` : ''}
      ${product === 'zcc' ? `<div class="op-row"><label class="df-ctl"><input type="checkbox" id="crZccProfiles"${z.zccp ? ' checked' : ''}><span>Include Client Connector app profiles and entitlements (clone to another tenant, or create a missing app profile)</span></label></div>
        <div class="df-hint">Passwords and the policy token are never read, copied or sent: a new app profile is created inactive and without any password. A clone matches each profile's groups by name in this tenant and never widens who a same-named profile here applies to; it copies the entitlements' switches without their group lists.</div>` : ''}
      ${singles.length ? `<details class="pa-details"><summary>Settings key by key</summary>${singles.map(t => `<div class="op-row"><label class="df-ctl"><span class="lbl">${E(t.label)}: keys to restore</span><input data-crkeys="${E(t.key)}" value="${E(z.keys[t.key] || '')}" autocomplete="off" aria-label="${E(t.label)}: keys to restore" placeholder="all keys"></label></div>`).join('')}</details>` : ''}
      <h3 class="op-h">4. Options</h3>
      <div class="op-row"><label class="df-ctl"><input type="checkbox" id="crKeep"${z.keep ? ' checked' : ''}><span>Keep each rule's state from the source (off: new rules are created disabled)</span></label></div>
      ${product === 'zia' ? `<div class="op-row"><label class="df-ctl"><input type="checkbox" id="crActivate"${z.activate ? ' checked' : ''}><span>Activate the ZIA changes as the last step</span></label></div>` : ''}
      <div class="op-row"><label class="df-ctl"><input type="checkbox" id="crAck"${z.ack ? ' checked' : ''}><span>I checked the licences (a clone is blocked while the target lacks a subscription the source has)</span></label></div>
      <div class="op-row"><label class="df-ctl"><input type="checkbox" id="crRollback"${z.rollback ? ' checked' : ''}><span>If the run stops or fails, roll back what it applied at once (otherwise Undo is offered)</span></label></div>
      ${psk ? `<details class="pa-details"><summary>VPN credentials: pre-shared keys</summary><div class="df-hint">No backup holds a pre-shared key. Type one for each VPN credential to create; it is sent with the apply only, never stored. Leave it blank to leave the credential out.</div>
        <div class="op-row"><label class="df-ctl"><span class="lbl">VPN credential (its FQDN or IP address)</span><input id="crPskName" autocomplete="off" aria-label="VPN credential name" placeholder="branch@corp.example"></label>
        <label class="df-ctl"><span class="lbl">Pre-shared key</span><input id="crPskValue" type="password" autocomplete="new-password" aria-label="Pre-shared key"></label>
        <button type="button" class="rp-btn" id="crPskAdd">Add the key</button><span class="df-chip" id="crPskCount">${Object.keys(z.psk).length} typed</span></div></details>` : ''}
      <div class="df-hint">Then click Preview the change below. Applying needs write mode, your permission to change the tenant, the assessor's name and the typed confirmation (DELETE n OBJECTS when the plan deletes).</div>
      <details class="pa-details" id="crTools"><summary>Backups, compare, schedule, templates</summary>
        <h3 class="op-h">Save a backup</h3>
        <div class="op-row"><button type="button" class="rp-btn primary" id="crSave">Save a backup now</button>
          <button type="button" class="rp-btn" id="crFromSample">Keep the sample tenant as a backup</button>
          <button type="button" class="rp-btn" id="crCache">Refresh the configuration cache</button></div>
        <div class="df-hint">Read-only: only what is in scope on the Scope page is read, and no secret is kept.</div>
        <h3 class="op-h">Compare, field by field</h3>
        <div class="op-row"><label class="df-ctl"><span class="lbl">Older</span><select id="crDiffOld" aria-label="Older side of the comparison"><option value="">Pick a backup…</option>${(res.backups || []).map(b => `<option value="${E(b.id)}"${z.diffOld === b.id ? ' selected' : ''}>${E(when(b.saved_at))} · ${E(b.tenant_label)}</option>`).join('')}</select></label>
          <label class="df-ctl"><span class="lbl">Newer</span><select id="crDiffNew" aria-label="Newer side of the comparison">${sideOpts(z.diffNew)}</select></label>
          <label class="df-ctl"><span class="lbl">Also ignore</span><input id="crIgnore" value="${E(z.ignore)}" autocomplete="off" aria-label="Also ignore these fields" placeholder="description, order"></label>
          <button type="button" class="rp-btn" id="crDiff">Compare</button></div>
        <h3 class="op-h">Scheduled backups</h3>
        <div class="op-row"><label class="df-ctl"><span class="lbl">Every (hours)</span><input id="crEvery" type="number" min="1" max="168" value="24" aria-label="Back up every so many hours"></label>
          <label class="df-ctl"><span class="lbl">Keep</span><input id="crKeepN" type="number" min="1" max="100" value="10" aria-label="How many backups to keep"></label>
          <label class="df-ctl"><input type="checkbox" id="crSchedOn"><span>On</span></label>
          <button type="button" class="rp-btn" id="crSched">Save the schedule</button></div>
        <div class="df-hint">For the saved profile picked in the Tenant list, if it remembers its secret. Scheduled backups only read; nothing is ever applied on its own.</div>
        <h3 class="op-h">Templates</h3>
        <div class="op-row"><label class="df-ctl"><span class="lbl">Object type</span><select id="crTplType" aria-label="Object type for the template">${types.filter(t => !t.singleton && t.clone).map(t => `<option value="${E(t.key)}"${z.tplType === t.key ? ' selected' : ''}>${E(t.label)}</option>`).join('')}</select></label>
          <label class="df-ctl"><span class="lbl">Names (one per line)</span><textarea id="crTplNames" rows="2" aria-label="Names of the objects for the template">${E(z.tplNames)}</textarea></label></div>
        <div class="op-row"><label class="df-ctl"><span class="lbl">Template name</span><input id="crTplName" value="${E(z.tplName)}" maxlength="80" aria-label="Template name"></label>
          <label class="df-ctl"><span class="lbl">Prefix to replace</span><input id="crTplStrip" value="${E(z.tplStrip)}" maxlength="20" autocomplete="off" aria-label="Prefix to replace with the template's prefix" placeholder="OLD-"></label>
          <button type="button" class="rp-btn" id="crTplMake">Make the template</button>
          <label class="df-ctl"><span class="lbl">Import a template file</span><input id="crTplFile" type="file" accept=".json,application/json" aria-label="Import a template file"></label></div>
        <h3 class="op-h">Rehearse</h3>
        <div class="op-row"><label class="df-ctl"><span class="lbl">Against</span><select id="crRehearseOn" aria-label="Rehearse against"><option value="sample">The sample tenant</option>${(res.backups || []).map(b => `<option value="${E(b.id)}">${E(when(b.saved_at))} · ${E(b.tenant_label)}</option>`).join('')}</select></label>
          <button type="button" class="rp-btn" id="crRehearse">Rehearse (plan only)</button></div>
        <div id="crOut" role="status" aria-live="polite"></div>
      </details>`;
    bind(res, where, S, H);
  }

  async function post(url, payload) {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d && typeof d.detail === 'string' ? d.detail : `HTTP ${r.status}`);
    return d;
  }
  async function reload(where, S, H, res) {
    try { const r = await fetch('/api/config-backups', { cache: 'no-store' }); if (r.ok) Object.assign(res, await r.json()); } catch (e) { /* kept */ }
    render(res, where, S, H);
    const tools = document.getElementById('crTools'); if (tools) tools.open = true;
  }
  function diffHtml(H, d) {
    const E = H.E;
    if (d.same) return `<div class="bp-card info"><div class="t">No differences</div><div>Compared ${E(d.compared)} object types, ignoring ${E('ids, change times, who changed it and counters')}.</div></div>`;
    return `<div class="bp-card info"><div class="t">${E(d.totals.added)} added, ${E(d.totals.removed)} removed, ${E(d.totals.changed)} changed</div><div class="df-hint">Matched by ${E(d.matched_by)}.</div></div>
      <div class="df-tablewrap"><table class="df-table"><caption class="sr-only">Differences field by field</caption>
      <thead><tr><th scope="col">Type</th><th scope="col">Object</th><th scope="col">Field</th><th scope="col">Older</th><th scope="col">Newer</th></tr></thead><tbody>
      ${(d.types || []).map(t => [].concat(t.added.map(n => `<tr><td>${E(t.label)}</td><td>${E(n)}</td><td>added</td><td></td><td></td></tr>`),
        t.removed.map(n => `<tr><td>${E(t.label)}</td><td>${E(n)}</td><td>removed</td><td></td><td></td></tr>`),
        t.changed.map(c => c.fields.map(f => `<tr><td>${E(t.label)}</td><td>${E(c.name)}</td><td>${E(f.path)}</td><td>${E(JSON.stringify(f.old))}</td><td>${E(JSON.stringify(f.new))}</td></tr>`).join(''))).join('')).join('')}
      </tbody></table></div>`;
  }

  function bind(res, where, S, H) {
    const z = st(S), $ = id => document.getElementById(id), out = () => $('crOut');
    const again = id => { render(res, where, S, H); const el = $(id) || where.querySelector(`input[name="${id}"]:checked`); if (el) el.focus(); };
    where.querySelectorAll('input[name="crSrc"]').forEach(r => r.addEventListener('change', () => { z.from = r.value; if (r.value === 'template') { z.target = 'other'; if (z.mode === 'full') z.mode = 'update_matching'; } again('crSrc'); }));
    where.querySelectorAll('input[name="crBackup"]').forEach(r => r.addEventListener('change', () => { z.backup = r.value; }));
    where.querySelectorAll('input[name="crTarget"]').forEach(r => r.addEventListener('change', () => { z.target = r.value; }));
    where.querySelectorAll('input[name="crMode"]').forEach(r => r.addEventListener('change', () => { z.mode = r.value; }));
    where.querySelectorAll('input[data-crtype]').forEach(cb => cb.addEventListener('change', () => { cb.checked ? z.types.add(cb.dataset.crtype) : z.types.delete(cb.dataset.crtype); }));
    where.querySelectorAll('input[data-crkeys]').forEach(i => i.addEventListener('input', () => { z.keys[i.dataset.crkeys] = i.value; }));
    const val = (id, key) => { const el = $(id); if (el) el.addEventListener(el.type === 'checkbox' ? 'change' : 'input', e => { z[key] = el.type === 'checkbox' ? e.target.checked : e.target.value; }); };
    const tb = $('crTb'); if (tb) tb.addEventListener('change', () => { z.tb = tb.checked; again('crTb'); });
    val('crZccProfiles', 'zccp');
    val('crTemplate', 'template'); val('crPrefix', 'prefix'); val('crKeep', 'keep'); val('crActivate', 'activate'); val('crAck', 'ack'); val('crRollback', 'rollback');
    val('crDiffOld', 'diffOld'); val('crDiffNew', 'diffNew'); val('crIgnore', 'ignore'); val('crTplType', 'tplType'); val('crTplNames', 'tplNames');
    val('crTplName', 'tplName'); val('crTplStrip', 'tplStrip');
    const pskAdd = $('crPskAdd');
    if (pskAdd) pskAdd.addEventListener('click', () => {
      const n = $('crPskName').value.trim(), v = $('crPskValue').value;
      if (!n || !v) { H.say('Type the VPN credential and its key.'); return; }
      z.psk[n] = v; $('crPskName').value = ''; $('crPskValue').value = ''; $('crPskCount').textContent = `${Object.keys(z.psk).length} typed`; H.say('Key kept in this page until the apply.');
    });
    where.querySelectorAll('button[data-crdel]').forEach(b => b.addEventListener('click', async () => {
      if (!window.confirm('Delete this backup file? This cannot be undone.')) return;
      try { await post(`/api/config-backups/${encodeURIComponent(b.dataset.crdel)}/delete`, {}); await reload(where, S, H, res); H.say('Backup deleted.'); } catch (e) { H.say(e.message); }
    }));
    const job = async (btn, url, payload, title, done) => {
      const box = out(); btn.disabled = true;
      try { const snap = await H.runJob(url, H.body(payload), box, title); const r = snap.result || {}; if (r.stopped) throw new Error('Stopped.'); await done(r, box); }
      catch (e) { H.fail(box, `${title}: not done`, e.message); } finally { btn.disabled = false; }
    };
    $('crSave').addEventListener('click', e => job(e.target, '/api/config-backups/save/start', { products: [PRODUCT[S.kind]] }, 'Saving a backup',
      async () => { await reload(where, S, H, res); H.say('Backup saved.'); }));
    $('crCache').addEventListener('click', e => job(e.target, '/api/config-cache/refresh/start', { products: [PRODUCT[S.kind]] }, 'Refreshing the configuration cache',
      async (r, box) => { const n = Object.values(r.changes || {}).reduce((a, c) => a + c.added.length + c.removed.length + c.changed.length, 0);
        box.innerHTML = `<div class="bp-card info"><div class="t">Cache refreshed</div><div>${H.E(r.objects)} objects; ${H.E(r.first ? 'first read' : `${n} changed since the last refresh`)}.</div></div>`; }));
    $('crFromSample').addEventListener('click', async () => {
      try { await post('/api/config-backups/from-snapshot', Object.assign({ snapshot_id: 'sample' }, { profile_id: (H.body({}) || {}).profile_id || '' })); await reload(where, S, H, res); H.say('The sample tenant was kept as a backup.'); }
      catch (e) { H.fail(out(), 'Not kept', e.message); }
    });
    $('crDiff').addEventListener('click', async e => {
      const ignore = z.ignore.split(/[\s,]+/).filter(Boolean);
      if (!z.diffOld) { H.say('Pick the older backup.'); return; }
      if (z.diffNew === 'live') return job(e.target, '/api/config-backups/diff-live/start', { backup_id: z.diffOld, ignore }, 'Comparing with the live tenant', async (r, box) => { box.innerHTML = diffHtml(H, r); });
      try { out().innerHTML = diffHtml(H, await post('/api/config-backups/diff', { old: z.diffOld, new: z.diffNew, ignore })); } catch (x) { H.fail(out(), 'Not compared', x.message); }
    });
    $('crSched').addEventListener('click', async () => {
      const pid = (H.body({}) || {}).profile_id;
      if (!pid) { H.fail(out(), 'Not saved', 'Pick a saved tenant profile in the Tenant list first.'); return; }
      try { const s = await post('/api/config-backups/schedule', { profile_id: pid, enabled: $('crSchedOn').checked, every_hours: Number($('crEvery').value), keep: Number($('crKeepN').value), products: [PRODUCT[S.kind]] });
        out().innerHTML = `<div class="bp-card info"><div class="t">Schedule ${s.enabled ? 'on' : 'off'}</div><div>Every ${H.E(s.every_hours)} hours, keeping ${H.E(s.keep)}.</div></div>`; }
      catch (x) { H.fail(out(), 'Not saved', x.message); }
    });
    $('crTplMake').addEventListener('click', async () => {
      const names = z.tplNames.split('\n').map(s => s.trim()).filter(Boolean), type = z.tplType || ($('crTplType') || {}).value;
      if (!z.backup) { H.fail(out(), 'No template', 'Pick the backup to take the objects from (step 1).'); return; }
      try { const d = await post('/api/config-templates/export', { backup_id: z.backup, objects: names.map(n => ({ type, name: n })), name: z.tplName, strip_prefix: z.tplStrip });
        await reload(where, S, H, res); H.say(`Template ${d.template.name} saved with ${d.template.objects} objects.`); }
      catch (x) { H.fail(out(), 'No template', x.message); }
    });
    $('crTplFile').addEventListener('change', async e => {
      const f = e.target.files && e.target.files[0]; if (!f) return;
      if (f.size > 2 * 1024 * 1024) { H.fail(out(), 'Not imported', 'A template file is at most 2 MB.'); return; }
      try { const d = await post('/api/config-templates/import', { content: await f.text() }); await reload(where, S, H, res); H.say(`Template ${d.template.name} imported.`); }
      catch (x) { H.fail(out(), 'Not imported', x.message); }
    });
    $('crRehearse').addEventListener('click', async () => {
      let spec; try { spec = buildSpec(S, H, true); } catch (x) { H.fail(out(), 'Nothing to rehearse', x.message, true); return; }
      try { const p = await post('/api/config-backups/rehearse', { operation: spec, target: $('crRehearseOn').value });
        out().innerHTML = `<div class="bp-card info"><div class="t">Rehearsal: ${H.E(p.counts.change)} to change, ${H.E(p.counts.noop)} already as asked, ${H.E(p.counts.excluded)} excluded</div><div>${H.E((p.blockers || []).concat(p.warnings || []).slice(0, 6).join(' '))}</div><div class="df-hint">Plan only: nothing was read from a tenant and nothing can be applied from it.</div></div>`; }
      catch (x) { H.fail(out(), 'Not rehearsed', x.message); }
    });
  }

  function buildSpec(S, H, rehearsal) {
    const z = st(S), product = PRODUCT[S.kind];
    const source = z.from === 'template' ? { template: z.template } : { backup: z.backup };
    if (!source.template && !source.backup) throw new Error(z.from === 'template' ? 'Pick a template.' : 'Pick the backup to restore from.');
    const target = z.from === 'template' ? 'other' : z.target;
    const pid = (H.body({}) || {}).profile_id || '';
    if (target === 'other' && !pid && !rehearsal) throw new Error("A clone or template writes only to a saved profile's tenant: pick it in the Tenant list above.");
    const keys = {};
    Object.entries(z.keys).forEach(([k, v]) => { const list = String(v || '').split(/[\s,]+/).filter(Boolean); if (list.length) keys[k] = list; });
    const spec = { type: S.kind, source, mode: z.mode, target, target_profile_id: target === 'other' ? pid : '', types: [...z.types].filter(k => (z.tb && z.from !== 'template') || !(S.cfgBound || new Set()).has(k)),
      keep_state: z.keep, activate: product !== 'zia' || z.activate, licence_ack: z.ack, rollback_on_stop: z.rollback, psk: Object.keys(z.psk) };
    if (z.from === 'template') spec.prefix = z.prefix;
    if (z.tb && product === 'zia' && z.from !== 'template') spec.include_tenant_bound = true;
    if (z.zccp && product === 'zcc' && z.from !== 'template') spec.include_zcc_profiles = true;
    if (Object.keys(keys).length) spec.settings_keys = keys;
    if (!spec.types.length) throw new Error('Tick at least one object type.');
    return spec;
  }

  function result(r, where, H) {
    const E = H.E, z = st(H.S), bits = [];
    z.psk = {};    // the typed keys are gone from this page once the apply ran
    const act = r.activation_step_result;
    if (act) bits.push(`ZIA activation: ${act.activated ? 'done' : E('not done: ' + (act.error || ''))}.`);
    else if (r.product === 'zia') bits.push('ZIA was not activated: what was written stays pending until Undo, or an activation in the portal.');
    if (r.rollback) bits.push(`Rolled back at once, as you asked: ${E(r.rollback.status)}${r.rollback.operation_id ? ` (recorded as ${E(r.rollback.operation_id)})` : ''}.`);
    if ((r.manual_steps || []).length) bits.push(`Manual steps: ${E(r.manual_steps.join('; '))}.`);
    const box = document.createElement('div');
    box.className = 'bp-card info';
    box.innerHTML = `<div class="t">Restore</div><div>${bits.join(' ')}</div>${r.repush ? `<div class="op-row"><button type="button" class="rp-btn" id="crRepush">Re-push what is missing (preview first)</button></div>` : ''}`;
    where.prepend(box);
    const b = document.getElementById('crRepush');
    if (b) b.addEventListener('click', () => H.preview('/api/operations/preview/start', H.body({ operation: r.repush })));
  }

  const def = { render, spec: (S, H) => buildSpec(S, H, false), result,
    applyExtra: S => { const z = st(S); return Object.keys(z.psk).length ? { secrets: Object.assign({}, z.psk) } : {}; } };
  Object.keys(PRODUCT).forEach(type => window.OPS_PLUGINS.register(Object.assign({ type }, def)));
})();
