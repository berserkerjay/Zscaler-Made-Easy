/* One ZIdentity user on Bulk changes (/report/operations, "Day-to-day admin"),
   on the shared engine (ops_zid_user.py): edit the user's names, email,
   department and groups (zid_user_edit), or reset its password or let it skip MFA
   (zid_user_reset: a raw call to ZIdentity's public API, typed
   "RESET <login>"). The page does the rest: Read from the tenant, Preview,
   the four gates, Apply, Undo. A temporary password ZIdentity answers is
   fetched once after the apply (POST /api/operations/zidentity/secret),
   shown in a read-only box and never kept by the page. Every tenant string
   is escaped (H.E). */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;
  let E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function st(S) {
    if (!S.zuser) S.zuser = { pick: '', display: null, first: null, last: null, email: null, dept: null, add: new Set(), remove: new Set(), act: 'reset_password' };
    return S.zuser;
  }
  function errs(res) {
    const rows = Object.entries((res && res.errors) || {});
    return rows.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${rows.map(([k, v]) => `<li>${E(k)}: ${E(v)}</li>`).join('')}</ul></div>` : '';
  }
  function picker(res, z, name) {
    const users = res.users || [];
    return `<div class="op-row"><label class="df-ctl"><span class="lbl">Find users by login name</span><input id="zuuSearch" type="search" value="${E(res.query || '')}" maxlength="100" aria-label="Find users by login name (contains)"></label>
        <button type="button" class="rp-btn" id="zuuSearchGo">Search</button>
        <span class="df-hint">${E(users.length)} user${users.length === 1 ? '' : 's'}${res.users_truncated ? ', the first ones only: search to narrow' : ''}.</span></div>
      <div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">ZIdentity users</caption>
        <thead><tr><th scope="col">Pick</th><th scope="col">User</th><th scope="col">Department</th><th scope="col">State</th><th scope="col">Note</th></tr></thead>
        <tbody>${users.map(u => `<tr><td><input type="radio" name="${E(name)}" value="${E(u.id)}" aria-label="Pick ${E(u.login_name)}"${z.pick === u.id ? ' checked' : ''}${u.locked ? ' disabled' : ''}></td>
          <td>${E(u.display_name)}<div class="df-by">${E(u.login_name)}</div></td><td>${E(u.department)}</td>
          <td><span class="df-chip ${u.status === 'enabled' ? 'st-ok' : ''}">${E(u.status)}</span></td><td class="df-hint">${E(u.locked)}</td></tr>`).join('') || '<tr><td colspan="5">No user matches.</td></tr>'}</tbody></table></div>`;
  }
  function wirePicker(res, where, S, H, name, again) {
    const z = st(S);
    where.querySelectorAll(`input[name="${name}"]`).forEach(r => r.addEventListener('change', () => {
      z.pick = r.value; z.display = z.first = z.last = z.email = z.dept = null; z.add.clear(); z.remove.clear(); again(name);
    }));
    const go = document.getElementById('zuuSearchGo');
    if (go) {
      go.addEventListener('click', () => H.read(document.getElementById('zuuSearch').value.trim()));
      document.getElementById('zuuSearch').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); go.click(); } });
    }
  }

  // ── Edit ──
  function renderEdit(res, where, S, H) {
    const z = st(S), u = (res.users || []).find(x => x.id === z.pick);
    const val = (k, f) => (z[k] == null ? (u ? u[f] : '') : z[k]);
    const groups = res.groups || [];
    const form = u ? `
      <div class="op-row"><label class="df-ctl"><span class="lbl">Display name</span><input id="zuuDisplay" value="${E(val('display', 'display_name'))}" maxlength="255" aria-label="Display name"></label>
        <label class="df-ctl"><span class="lbl">First name</span><input id="zuuFirst" value="${E(val('first', 'first_name'))}" maxlength="255" aria-label="First name"></label>
        <label class="df-ctl"><span class="lbl">Last name</span><input id="zuuLast" value="${E(val('last', 'last_name'))}" maxlength="255" aria-label="Last name"></label>
        <label class="df-ctl"><span class="lbl">Email</span><input id="zuuEmail" type="email" value="${E(val('email', 'primary_email'))}" maxlength="255" autocomplete="off" aria-label="Email"></label></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Department</span><select id="zuuDept" aria-label="Department">
        <option value="">(none)</option>${(res.departments || []).map(d => `<option value="${E(d.id)}"${(z.dept == null ? u.department_id : z.dept) === d.id ? ' selected' : ''}>${E(d.name)}</option>`).join('')}
      </select></label><span class="df-hint">The departments the directory's users already have.</span></div>
      <fieldset class="op-inline"><legend>Groups (adding or removing one needs EDIT and the login typed)</legend>
        <ul class="op-checks">${groups.map(g => `<li><label><input type="checkbox" data-zuu-add="${E(g.id)}"${z.add.has(g.id) ? ' checked' : ''}${g.dynamic ? ' disabled' : ''}> Add to ${E(g.name)}</label>
          <label><input type="checkbox" data-zuu-rem="${E(g.id)}"${z.remove.has(g.id) ? ' checked' : ''}${g.dynamic ? ' disabled' : ''}> Remove from ${E(g.name)}</label>${g.dynamic ? ' <span class="df-hint">dynamic: its rule decides</span>' : ''}</li>`).join('') || '<li class="df-hint">No group could be read.</li>'}</ul></fieldset>
      <div class="df-hint">Only what you change is sent; the rest of the user goes back as read. Undo puts it back.</div>` : '<p class="df-hint">Pick a user to edit.</p>';
    where.innerHTML = `${errs(res)}${picker(res, z, 'zuuPick')}${form}`;
    const again = id => { renderEdit(res, where, S, H); const el = document.getElementById(id) || where.querySelector(`input[name="${id}"]:checked`); if (el) el.focus(); };
    wirePicker(res, where, S, H, 'zuuPick', again);
    [['zuuDisplay', 'display'], ['zuuFirst', 'first'], ['zuuLast', 'last'], ['zuuEmail', 'email']].forEach(([id, k]) => { const el = document.getElementById(id); if (el) el.addEventListener('input', () => { z[k] = el.value; }); });
    const d = document.getElementById('zuuDept'); if (d) d.addEventListener('change', () => { z.dept = d.value; });
    where.querySelectorAll('input[data-zuu-add]').forEach(cb => cb.addEventListener('change', () => { cb.checked ? z.add.add(cb.dataset.zuuAdd) : z.add.delete(cb.dataset.zuuAdd); }));
    where.querySelectorAll('input[data-zuu-rem]').forEach(cb => cb.addEventListener('change', () => { cb.checked ? z.remove.add(cb.dataset.zuuRem) : z.remove.delete(cb.dataset.zuuRem); }));
    S.zuserRes = res;
  }
  function specEdit(S) {
    const z = st(S), res = S.zuserRes || {}, u = (res.users || []).find(x => x.id === z.pick);
    if (!u) throw new Error('Pick the user.');
    const set = {};
    [['display', 'display_name'], ['first', 'first_name'], ['last', 'last_name'], ['email', 'primary_email']].forEach(([k, f]) => { if (z[k] != null && z[k].trim() !== (u[f] || '')) set[f] = z[k].trim(); });
    if (z.dept != null && z.dept !== (u.department_id || '')) {
      const dd = (res.departments || []).find(x => x.id === z.dept);
      set.department = dd ? { id: dd.id, name: dd.name } : null;
    }
    const groups = { add: [...z.add], remove: [...z.remove] };
    if (!Object.keys(set).length && !groups.add.length && !groups.remove.length) throw new Error('Change at least one field or group.');
    return { type: 'zid_user_edit', id: u.id, set, groups };
  }

  // ── Reset ──
  function renderReset(res, where, S, H) {
    const z = st(S);
    where.innerHTML = `${errs(res)}${picker(res, z, 'zurPick')}
      <div class="op-row"><fieldset class="op-inline"><legend>What to do</legend>
        <label><input type="radio" name="zurAct" value="reset_password"${z.act === 'reset_password' ? ' checked' : ''}> Reset the password</label>
        <label><input type="radio" name="zurAct" value="skip_mfa"${z.act === 'skip_mfa' ? ' checked' : ''}> Let the user skip MFA</label></fieldset></div>
      <div class="bp-card warn"><div class="t">Cannot be undone</div><div>You type RESET and the user's login name to confirm, and your name is recorded as the assessor.</div></div>
      <ul class="op-checks">${(res.raw_calls || []).map(n => `<li class="df-hint">${E(n)}</li>`).join('')}<li class="df-hint">${E(res.password_once || '')}</li></ul>`;
    const again = id => { renderReset(res, where, S, H); const el = document.getElementById(id) || where.querySelector(`input[name="${id}"]:checked`); if (el) el.focus(); };
    wirePicker(res, where, S, H, 'zurPick', again);
    where.querySelectorAll('input[name="zurAct"]').forEach(r => r.addEventListener('change', () => { z.act = r.value; }));
  }
  function specReset(S) {
    const z = st(S);
    if (!z.pick) throw new Error('Pick the user.');
    return { type: 'zid_user_reset', id: z.pick, action: z.act };
  }

  // ── A temporary password, fetched once after the apply ──
  async function showPassword(r, where, H) {
    for (const s of r.one_time_secrets || []) {
      const box = document.createElement('div');
      box.className = 'bp-card warn';
      box.setAttribute('role', 'alert');
      where.prepend(box);
      try {
        const q = await fetch('/api/operations/zidentity/secret', { method: 'POST', headers: { 'Content-Type': 'application/json' }, cache: 'no-store', body: JSON.stringify({ token: s.token }) });
        const d = await q.json().catch(() => ({}));
        if (!q.ok) throw new Error(typeof d.detail === 'string' && d.detail ? d.detail : `HTTP ${q.status}`);
        box.innerHTML = `<div class="t">ZIdentity's answer for ${E(d.name)}: give it to the user now</div>
          <div>It is shown this once. This app does not keep it; if it is lost, reset the password again.</div>
          <div class="op-row"><label class="df-ctl"><span class="lbl">Temporary password</span><input class="zuu-secret" readonly autocomplete="off" spellcheck="false" aria-label="Temporary password"></label>
            <button type="button" class="rp-btn zuu-copy">Copy</button></div>`;
        const inp = box.querySelector('.zuu-secret'); inp.value = d.secret;
        box.querySelector('.zuu-copy').addEventListener('click', async () => {
          try { await navigator.clipboard.writeText(inp.value); H.say('Copied.'); } catch (e) { inp.select(); H.say('Select it and copy it.'); }
        });
        H.say('The temporary password is shown once: give it to the user now.');
      } catch (e) {
        box.innerHTML = `<div class="t">The answer could not be shown</div><div>${E(e.message)}</div>`;
      }
    }
  }

  window.OPS_PLUGINS.register({ type: 'zid_user_edit', render(res, where, S, H) { E = H.E || E; renderEdit(res, where, S, H); }, spec: S => specEdit(S) });
  window.OPS_PLUGINS.register({ type: 'zid_user_reset', render(res, where, S, H) { E = H.E || E; S.zuserRes = res; renderReset(res, where, S, H); }, spec: S => specReset(S),
    result(r, where, H) { E = H.E || E; showPassword(r, where, H); } });
}());
