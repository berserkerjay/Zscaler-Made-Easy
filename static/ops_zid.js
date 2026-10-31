/* ZIdentity group members on Bulk changes (/report/operations, ops_zid.py).
   Pick a group (names and member counts only: the directory is never
   listed), type the sign-in names to add or remove, then the page's own
   Preview, the gates (the group's name is typed to confirm), Apply and Undo. */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;

  function st(S) {
    if (!S.zid) S.zid = { group: '', add: '', remove: '' };
    return S.zid;
  }
  function errs(H, res) {
    const rows = Object.entries((res && res.errors) || {});
    return rows.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${rows.map(([k, v]) => `<li>${H.E(k)}: ${H.E(v)}</li>`).join('')}</ul></div>` : '';
  }
  function names(text) {
    return String(text || '').split(/[\s,;]+/).map(x => x.trim()).filter(Boolean);
  }
  function render(res, where, S, H) {
    const E = H.E, z = st(S), groups = res.groups || [], max = res.max_people || 50;
    where.innerHTML = `${errs(H, res)}
      <p class="df-hint">Pick one group, then type the sign-in names to add or remove, one per line or separated by commas (at most ${E(max)} on each side). The directory is never listed here. Nothing is written until you apply, and you type the group's name to confirm.</p>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Group</span><select id="zidGroup" aria-label="ZIdentity group">
        <option value="">Pick a group…</option>${groups.map(g => `<option value="${E(g.id)}"${g.id === z.group ? ' selected' : ''}${g.dynamic ? ' disabled' : ''}>${E(g.name)}${g.members != null ? ` (${E(g.members)} member${g.members === 1 ? '' : 's'})` : ''}${g.dynamic ? ' (dynamic: its rule decides)' : ''}${g.source ? ` · ${E(g.source)}` : ''}</option>`).join('')}
      </select></label></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Add these people</span><textarea id="zidAdd" rows="3" maxlength="8000" aria-label="Sign-in names to add to the group" spellcheck="false">${E(z.add)}</textarea></label></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Remove these people</span><textarea id="zidRemove" rows="3" maxlength="8000" aria-label="Sign-in names to remove from the group" spellcheck="false">${E(z.remove)}</textarea></label></div>
      <div class="df-hint">A group synced from the identity provider (SCIM) can be changed, but its next sync may undo it: change it there to make it last.</div>`;
    document.getElementById('zidGroup').addEventListener('change', e => { z.group = e.target.value; });
    document.getElementById('zidAdd').addEventListener('input', e => { z.add = e.target.value; });
    document.getElementById('zidRemove').addEventListener('input', e => { z.remove = e.target.value; });
  }
  function spec(S) {
    const z = st(S);
    if (!z.group) throw new Error('Pick the group.');
    const add = names(z.add), remove = names(z.remove);
    if (!add.length && !remove.length) throw new Error('Type at least one sign-in name to add or remove.');
    return { type: 'zid_group_members', group: z.group, add, remove };
  }
  window.OPS_PLUGINS.register({ type: 'zid_group_members', render, spec });
})();
