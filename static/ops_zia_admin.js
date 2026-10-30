/* Day-to-day ZIA admin on Bulk changes (/report/operations, "Day-to-day admin").
   Two forms on the shared engine: users, groups and departments
   (ops_zia_directory.py) and hosted PAC files (ops_zia_pac.py). The page does
   the rest: Read from the tenant, Preview (every item before and after; for a
   PAC the line diff and both checks), the four gates, Apply, Undo.
   Every tenant string is escaped (H.E); a PAC's text is only ever shown as
   text, never run. */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;

  function errs(H, res) {
    const rows = Object.entries((res && res.errors) || {});
    return rows.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${rows.map(([k, v]) => `<li>${H.E(k)}: ${H.E(v)}</li>`).join('')}</ul></div>` : '';
  }
  const opts = (H, rows, sel, none) => (none ? `<option value="">${H.E(none)}</option>` : '') +
    rows.map(r => `<option value="${H.E(r.id)}"${String(sel) === String(r.id) ? ' selected' : ''}${r.locked ? ' disabled' : ''}>${H.E(r.name)}${r.locked ? ' (left alone)' : ''}</option>`).join('');
  const picked = el => el ? [...el.selectedOptions].map(o => o.value).filter(Boolean) : [];

  // ── Users, groups and departments ──
  function zd(S) {
    if (!S.zd) S.zd = { mode: 'users', act: 'edit', pick: new Set(), dept: '', add: [], remove: [], newName: '', newEmail: '', newDept: '', newGroups: [],
      gkind: 'group', gName: '', rename: '', renameTo: '', gdel: new Set() };
    return S.zd;
  }
  function renderDirectory(res, where, S, H) {
    const E = H.E, z = zd(S), users = res.users || [], groups = res.groups || [], depts = res.departments || [];
    const modes = [['users', 'Change or delete users'], ['new_user', 'Add a user'], ['groups', 'Groups and departments']];
    let body = '';
    if (z.mode === 'users') {
      body = `<div class="op-row"><label class="df-ctl"><span class="lbl">Find users by name</span><input id="zdSearch" type="search" value="${E(res.query || '')}" maxlength="100" aria-label="Find users by name (starts with)"></label>
          <button type="button" class="rp-btn" id="zdSearchGo">Search</button>
          <span class="df-hint">${E(users.length)} user${users.length === 1 ? '' : 's'}${res.users_truncated ? ', the first ones only: search to narrow' : ''}.</span></div>
        <div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">ZIA users</caption>
          <thead><tr><th scope="col">Pick</th><th scope="col">User</th><th scope="col">Department</th><th scope="col">Groups</th><th scope="col">Note</th></tr></thead>
          <tbody>${users.map(u => `<tr><td><input type="checkbox" data-zu="${E(u.id)}" aria-label="Pick ${E(u.name)}"${z.pick.has(u.id) ? ' checked' : ''}${u.locked ? ' disabled' : ''}></td>
            <td>${E(u.name)}<div class="df-by">${E(u.email)}</div></td><td>${E(u.department)}</td><td>${E((u.groups || []).join(', '))}</td><td class="df-hint">${E(u.locked)}</td></tr>`).join('')
            || '<tr><td colspan="5">No user matches.</td></tr>'}</tbody></table></div>
        <div class="op-row"><fieldset class="op-inline"><legend>For the picked users</legend>
          <label><input type="radio" name="zdUserAct" value="edit"${z.act === 'edit' ? ' checked' : ''}> Change department or groups</label>
          <label><input type="radio" name="zdUserAct" value="delete"${z.act === 'delete' ? ' checked' : ''}> Delete (cannot be undone)</label></fieldset></div>
        ${z.act === 'edit' ? `<div class="op-row"><label class="df-ctl"><span class="lbl">Department</span><select id="zdDept" aria-label="New department">${opts(H, depts, z.dept, 'No change')}</select></label>
          <label class="df-ctl"><span class="lbl">Add to groups</span><select id="zdAdd" multiple size="4" aria-label="Groups to add the picked users to">${opts(H, groups, '', '').replace(/<option value="([^"]*)"/g, (m, v) => z.add.includes(v) ? `${m} selected` : m)}</select></label>
          <label class="df-ctl"><span class="lbl">Remove from groups</span><select id="zdRemove" multiple size="4" aria-label="Groups to remove the picked users from">${opts(H, groups, '', '').replace(/<option value="([^"]*)"/g, (m, v) => z.remove.includes(v) ? `${m} selected` : m)}</select></label></div>`
          : '<div class="df-hint">A delete asks its name typed when you apply, and cannot be undone.</div>'}`;
    } else if (z.mode === 'new_user') {
      body = `<div class="op-row"><label class="df-ctl"><span class="lbl">Name</span><input id="zdNewName" value="${E(z.newName)}" maxlength="255" aria-label="New user's name" placeholder="Sam Lee"></label>
          <label class="df-ctl"><span class="lbl">Email</span><input id="zdNewEmail" type="email" value="${E(z.newEmail)}" maxlength="254" aria-label="New user's email" placeholder="sam.lee@example.com"></label></div>
        <div class="op-row"><label class="df-ctl"><span class="lbl">Department</span><select id="zdNewDept" aria-label="New user's department">${opts(H, depts, z.newDept, 'Pick one…')}</select></label>
          <label class="df-ctl"><span class="lbl">Groups</span><select id="zdNewGroups" multiple size="4" aria-label="New user's groups">${opts(H, groups, '', '').replace(/<option value="([^"]*)"/g, (m, v) => z.newGroups.includes(v) ? `${m} selected` : m)}</select></label></div>
        <div class="df-hint">No password is set here: a user who signs in with a ZIA password gets it from the ZIA Admin Portal.</div>`;
    } else {
      const list = z.gkind === 'group' ? groups : depts, word = z.gkind === 'group' ? 'group' : 'department';
      body = `<div class="op-row"><fieldset class="op-inline"><legend>Change</legend>
          <label><input type="radio" name="zdGKind" value="group"${z.gkind === 'group' ? ' checked' : ''}> Groups</label>
          <label><input type="radio" name="zdGKind" value="department"${z.gkind === 'department' ? ' checked' : ''}> Departments</label></fieldset></div>
        <div class="op-row"><label class="df-ctl"><span class="lbl">New ${E(word)}</span><input id="zdGName" value="${E(z.gName)}" maxlength="255" aria-label="Name of a new ${E(word)}"></label></div>
        <div class="op-row"><label class="df-ctl"><span class="lbl">Rename</span><select id="zdRename" aria-label="The ${E(word)} to rename">${opts(H, list, z.rename, 'No rename')}</select></label>
          <label class="df-ctl"><span class="lbl">To</span><input id="zdRenameTo" value="${E(z.renameTo)}" maxlength="255" aria-label="Its new name"></label></div>
        <ul class="op-checks">${list.map(g => `<li><label><input type="checkbox" data-zg="${E(g.id)}"${z.gdel.has(g.id) ? ' checked' : ''}${g.locked ? ' disabled' : ''}> Delete ${E(g.name)}${g.locked ? ` <span class="df-hint">(${E(g.locked)})</span>` : ''}</label></li>`).join('') || `<li class="df-hint">No ${E(word)}.</li>`}</ul>
        <div class="df-hint">A delete asks its name typed when you apply and cannot be undone. Groups and departments from the identity provider are left alone.</div>`;
    }
    where.innerHTML = `${errs(H, res)}
      <div class="op-row"><fieldset class="op-inline"><legend>What to do</legend>${modes.map(([v, l]) => `<label><input type="radio" name="zdMode" value="${v}"${z.mode === v ? ' checked' : ''}> ${E(l)}</label>`).join('')}</fieldset></div>
      ${body}
      <ul class="op-checks">${(res.not_possible || []).map(n => `<li class="df-hint">${E(n)}</li>`).join('')}</ul>`;
    const again = id => { renderDirectory(res, where, S, H); const el = document.getElementById(id) || where.querySelector(`input[name="${id}"]:checked`); if (el) el.focus(); };
    where.querySelectorAll('input[name="zdMode"]').forEach(r => r.addEventListener('change', () => { z.mode = r.value; again('zdMode'); }));
    where.querySelectorAll('input[name="zdUserAct"]').forEach(r => r.addEventListener('change', () => { z.act = r.value; again('zdUserAct'); }));
    where.querySelectorAll('input[name="zdGKind"]').forEach(r => r.addEventListener('change', () => { z.gkind = r.value; z.rename = ''; z.gdel.clear(); again('zdGKind'); }));
    where.querySelectorAll('input[data-zu]').forEach(cb => cb.addEventListener('change', () => { cb.checked ? z.pick.add(cb.dataset.zu) : z.pick.delete(cb.dataset.zu); }));
    where.querySelectorAll('input[data-zg]').forEach(cb => cb.addEventListener('change', () => { cb.checked ? z.gdel.add(cb.dataset.zg) : z.gdel.delete(cb.dataset.zg); }));
    const bind = (id, key, multi) => { const el = document.getElementById(id); if (el) el.addEventListener(multi ? 'change' : (el.tagName === 'SELECT' ? 'change' : 'input'), () => { z[key] = multi ? picked(el) : el.value; }); };
    bind('zdDept', 'dept'); bind('zdAdd', 'add', true); bind('zdRemove', 'remove', true); bind('zdNewName', 'newName'); bind('zdNewEmail', 'newEmail');
    bind('zdNewDept', 'newDept'); bind('zdNewGroups', 'newGroups', true); bind('zdGName', 'gName'); bind('zdRename', 'rename'); bind('zdRenameTo', 'renameTo');
    const go = document.getElementById('zdSearchGo');
    if (go) {
      go.addEventListener('click', () => H.read(document.getElementById('zdSearch').value.trim()));
      document.getElementById('zdSearch').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); go.click(); } });
    }
  }
  function specDirectory(S) {
    const z = zd(S), changes = [];
    if (z.mode === 'users') {
      if (!z.pick.size) throw new Error('Pick at least one user.');
      [...z.pick].forEach(id => {
        if (z.act === 'delete') { changes.push({ kind: 'user', action: 'delete', id }); return; }
        const c = { kind: 'user', action: 'edit', id, groups_add: z.add, groups_remove: z.remove };
        if (z.dept) c.department = z.dept;
        changes.push(c);
      });
      if (z.act === 'edit' && !z.dept && !z.add.length && !z.remove.length) throw new Error('Pick a department or the groups to add or remove.');
    } else if (z.mode === 'new_user') {
      if (!z.newName.trim() || !z.newEmail.trim()) throw new Error("Give the new user's name and email.");
      if (!z.newDept) throw new Error("Pick the new user's department.");
      changes.push({ kind: 'user', action: 'create', name: z.newName.trim(), email: z.newEmail.trim(), department: z.newDept, groups: z.newGroups });
    } else {
      if (z.gName.trim()) changes.push({ kind: z.gkind, action: 'create', name: z.gName.trim() });
      if (z.rename && z.renameTo.trim()) changes.push({ kind: z.gkind, action: 'edit', id: z.rename, name: z.renameTo.trim() });
      z.gdel.forEach(id => changes.push({ kind: z.gkind, action: 'delete', id }));
      if (!changes.length) throw new Error(`Name a new ${z.gkind}, pick one to rename, or tick the ones to delete.`);
    }
    return { type: 'zia_directory', changes };
  }

  // ── PAC files ──
  function zp(S) {
    if (!S.zp) S.zp = { pick: '', act: 'validate', version: '', text: '', msg: '', name: '', domain: '', desc: '' };
    return S.zp;
  }
  const ACTS = [['validate', 'Validate'], ['new_version', 'New version (staged)'], ['deploy', 'Switch the active version'], ['clone', 'Clone'],
    ['create', 'New PAC file'], ['delete', 'Delete']];
  function renderPac(res, where, S, H) {
    const E = H.E, z = zp(S), files = res.pac_files || [], f = files.find(x => x.id === z.pick);
    const needFile = z.act !== 'create' && !(z.act === 'validate' && !f);
    const vers = (f && f.versions) || [];
    const verSel = `<label class="df-ctl"><span class="lbl">${z.act === 'deploy' ? 'Version to make active' : 'From version'}</span><select id="zpVer" aria-label="PAC version">
        ${vers.map(v => `<option value="${E(v.version)}"${String(z.version || (f && f.version) || '') === String(v.version) ? ' selected' : ''}>${E(v.version)} · ${E(v.status || '')}${v.commit_message ? ' · ' + E(v.commit_message) : ''}</option>`).join('')}</select></label>`;
    const textBox = `<label class="op-block"><span class="lbl">PAC text (it is checked, never run)</span><textarea id="zpText" rows="12" spellcheck="false" aria-label="PAC text">${E(z.text)}</textarea></label>
      ${f ? '<div class="op-row"><button type="button" class="rp-btn" id="zpLoad">Copy the active text into the box</button></div>' : ''}`;
    const named = `<div class="op-row"><label class="df-ctl"><span class="lbl">New PAC file name</span><input id="zpName" value="${E(z.name)}" maxlength="63" aria-label="New PAC file name" placeholder="branch.pac"></label>
        <label class="df-ctl"><span class="lbl">Domain</span><input id="zpDomain" value="${E(z.domain || (f && f.domain) || '')}" maxlength="253" aria-label="The organisation's domain it applies to" placeholder="example.com"></label>
        <label class="df-ctl"><span class="lbl">Description</span><input id="zpDesc" value="${E(z.desc)}" maxlength="1024" aria-label="Description"></label></div>`;
    const msg = `<div class="op-row"><label class="df-ctl"><span class="lbl">Commit message</span><input id="zpMsg" value="${E(z.msg)}" maxlength="255" aria-label="Commit message"></label></div>`;
    const extra = { validate: (f ? verSel : '') + textBox, new_version: verSel + textBox + msg, deploy: verSel, clone: verSel + named + msg,
      create: named + textBox + msg, delete: '<div class="df-hint">The PAC file and every version of it are deleted. You type its name to confirm, and it cannot be undone.</div>' }[z.act];
    where.innerHTML = `${errs(H, res)}
      <p class="df-hint">${E(res.never_run || '')}</p>
      <div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">Hosted PAC files</caption>
        <thead><tr><th scope="col">Pick</th><th scope="col">PAC file</th><th scope="col">Active version</th><th scope="col">Versions</th><th scope="col">URL</th></tr></thead>
        <tbody>${files.map(x => `<tr><td><input type="radio" name="zpPick" value="${E(x.id)}" aria-label="Pick ${E(x.name)}"${z.pick === x.id ? ' checked' : ''}></td>
          <td>${E(x.name)}<div class="df-by">${E(x.domain)}${x.editable ? '' : ' · not editable'}</div></td><td>${E(x.version)}</td><td>${E((x.versions || []).length)}</td><td class="df-hint">${E(x.url)}</td></tr>`).join('')
          || '<tr><td colspan="5">The tenant has no hosted PAC file.</td></tr>'}</tbody></table></div>
      ${f ? `<details class="pa-details"><summary>Active text of ${E(f.name)} (version ${E(f.version)}, ${E(f.lines)} lines)</summary><div class="pa-log" id="zpView"></div>${f.content_cut ? '<div class="df-hint">Cut for display; the preview reads all of it.</div>' : ''}</details>` : ''}
      <div class="op-row"><fieldset class="op-inline"><legend>What to do</legend>${ACTS.map(([v, l]) => `<label><input type="radio" name="zpAct" value="${v}"${z.act === v ? ' checked' : ''}> ${E(l)}</label>`).join('')}</fieldset></div>
      ${needFile && !f ? '<div class="df-hint">Pick the PAC file above.</div>' : extra}`;
    const view = document.getElementById('zpView'); if (view) view.textContent = f.content || '';
    const again = id => { renderPac(res, where, S, H); const el = document.getElementById(id) || where.querySelector(`input[name="${id}"]:checked`); if (el) el.focus(); };
    where.querySelectorAll('input[name="zpPick"]').forEach(r => r.addEventListener('change', () => { z.pick = r.value; z.version = ''; again('zpPick'); }));
    where.querySelectorAll('input[name="zpAct"]').forEach(r => r.addEventListener('change', () => { z.act = r.value; again('zpAct'); }));
    [['zpText', 'text'], ['zpMsg', 'msg'], ['zpName', 'name'], ['zpDomain', 'domain'], ['zpDesc', 'desc']].forEach(([id, k]) => {
      const el = document.getElementById(id); if (el) el.addEventListener('input', () => { z[k] = el.value; });
    });
    const ver = document.getElementById('zpVer'); if (ver) { if (!z.version) z.version = ver.value; ver.addEventListener('change', () => { z.version = ver.value; }); }
    const load = document.getElementById('zpLoad');
    if (load) load.addEventListener('click', () => { z.text = f.content || ''; document.getElementById('zpText').value = z.text; H.say('The active text is in the box.'); });
  }
  function specPac(S) {
    const z = zp(S), spec = { type: 'zia_pac', action: z.act };
    if (z.act !== 'create' && z.pick) spec.pac_id = z.pick;
    if (z.act !== 'create' && z.act !== 'validate' && !z.pick) throw new Error('Pick the PAC file.');
    if (['new_version', 'deploy', 'clone'].includes(z.act) || (z.act === 'validate' && z.pick && z.version)) spec.version = Number(z.version);
    if (['validate', 'new_version', 'create'].includes(z.act)) { if (!z.text.trim()) throw new Error('Paste the PAC text.'); spec.content = z.text; }
    if (['create', 'clone'].includes(z.act)) { spec.name = z.name.trim(); spec.domain = (z.domain || '').trim(); spec.description = z.desc.trim(); }
    if (['new_version', 'create', 'clone'].includes(z.act)) spec.commit_message = z.msg.trim();
    return spec;
  }
  // The preview's diff and the two checks (this app's parse, ZIA's validator).
  function planPac(p, where, H) {
    const E = H.E, d = p.diff, c = p.pac_check;
    const box = document.createElement('div');
    box.className = 'op-pac-plan';
    let html = '';
    if (c) {
      const loc = c.local || {}, zia = c.zia || {};
      html += `<h3 class="op-h">Checks</h3><ul class="op-gates">
        <li><span class="df-chip ${loc.ok && loc.has_function ? 'st-ok' : 'st-warn'}">${loc.ok && loc.has_function ? 'parsed' : 'check'}</span> This app's parse (never run): ${E(loc.ok ? (loc.has_function ? 'FindProxyForURL found' : 'no FindProxyForURL') : loc.error)}${(loc.direct || []).length ? `; DIRECT for ${E(loc.direct.join(', '))}` : ''}.</li>
        <li><span class="df-chip ${zia.ran ? (zia.success ? 'st-ok' : 'st-fail') : 'st-warn'}">${zia.ran ? (zia.success ? 'valid' : 'refused') : 'not asked'}</span> ZIA's validator: ${E(zia.ran ? (zia.success ? 'no error' : (zia.messages || []).map(m => `line ${m.line}: ${m.message}`).join('; ') || 'refused') : zia.error || '')}.</li></ul>`;
    }
    if (d) {
      html += `<h3 class="op-h">Changes: ${E(d.from)} → ${E(d.to)}</h3><div class="df-hint">${d.same ? 'No line changes.' : `${E(d.added)} line${d.added === 1 ? '' : 's'} added, ${E(d.removed)} removed${d.cut ? ' (the diff is cut)' : ''}. Lines starting with + are added, with - removed.`}</div>
        <div class="pa-log op-diff" role="region" aria-label="Line changes" tabindex="0"></div>`;
    }
    box.innerHTML = html;
    const pre = box.querySelector('.op-diff');
    if (pre) (d.lines || []).forEach(line => {
      const s = document.createElement('div');
      s.textContent = line;
      if (line.startsWith('+') && !line.startsWith('+++')) s.className = 'op-add';
      else if (line.startsWith('-') && !line.startsWith('---')) s.className = 'op-del';
      pre.appendChild(s);
    });
    if (html) where.appendChild(box);
  }

  window.OPS_PLUGINS.register({ type: 'zia_directory', render: (res, where, S, H) => renderDirectory(res, where, S, H), spec: S => specDirectory(S) });
  window.OPS_PLUGINS.register({ type: 'zia_pac', render: (res, where, S, H) => renderPac(res, where, S, H), spec: S => specPac(S), plan: (p, where, H) => planPac(p, where, H) });
}());
