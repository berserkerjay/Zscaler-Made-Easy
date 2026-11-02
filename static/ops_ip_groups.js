/* IP source and destination groups on Bulk changes (/report/operations,
   "Change"), on the shared engine (ops_ip_groups.py): edit an IP source
   group, delete a source or destination group (refused while a rule uses
   it), or import groups from a CSV; the export saves the groups as CSV. The
   page does the rest: Preview, the gates, Apply and Undo. The CSV file is
   read in the browser as text (at most 1 MB) and sent with the preview;
   nothing in it is ever run. Every tenant string is escaped (H.E). */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;
  const MAX = 1024 * 1024;

  function st(S) {
    if (!S.ipg) S.ipg = { act: 'source_edit', pick: '', newName: '', newDesc: '', add: '', remove: '', del: '', csv: '', mode: 'merge' };
    return S.ipg;
  }
  function lines(t) { return String(t || '').split(/[\s,;]+/).map(x => x.trim()).filter(Boolean); }
  function table(E, rows, name, z, radioOf) {
    return `<div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">IP groups and the rules that use them</caption>
      <thead><tr><th scope="col">Pick</th><th scope="col">Group</th><th scope="col">Entries</th><th scope="col">Used by</th></tr></thead>
      <tbody>${rows.map(g => `<tr><td><input type="radio" name="${E(name)}" value="${E(radioOf(g))}" aria-label="Pick ${E(g.name)}"${z === radioOf(g) ? ' checked' : ''}${g.locked ? ' disabled' : ''}></td>
        <td>${E(g.name)}<div class="df-by">${E(g.kind)}${g.type ? ' · ' + E(g.type) : ''}${g.locked ? ' · predefined' : ''}</div></td>
        <td>${E(g.count)}<div class="df-by">${E((g.entries || []).slice(0, 5).join(', '))}${g.count > 5 ? '…' : ''}</div></td>
        <td>${(g.used_by || []).map(r => `${E(r.policy_label)} ${E(r.order)}: ${E(r.name)}`).join('<br>') || '<span class="df-hint">no rule read here</span>'}</td></tr>`).join('') || '<tr><td colspan="4">No group.</td></tr>'}</tbody></table></div>`;
  }
  function render(res, where, S, H) {
    const E = H.E, z = st(S), src = res.source_groups || [], dst = res.destination_groups || [];
    const errs = Object.entries(res.errors || {});
    let body = '';
    if (z.act === 'source_edit') {
      body = `${table(E, [{ id: '', name: 'A new IP source group', kind: 'source', count: 0, entries: [], used_by: [] }].concat(src), 'ipgPick', z.pick, g => String(g.id))}
        ${z.pick === '' ? `<div class="op-row"><label class="df-ctl"><span class="lbl">New group name</span><input id="ipgNewName" value="${E(z.newName)}" maxlength="128" aria-label="New IP source group name"></label>
          <label class="df-ctl"><span class="lbl">Description</span><input id="ipgNewDesc" value="${E(z.newDesc)}" maxlength="255" aria-label="Description of the new group"></label></div>` : ''}
        <div class="op-row"><label class="df-ctl"><span class="lbl">Addresses to add</span><textarea id="ipgAdd" rows="3" maxlength="200000" spellcheck="false" aria-label="IPv4 addresses, blocks or ranges to add">${E(z.add)}</textarea></label>
          ${z.pick !== '' ? `<label class="df-ctl"><span class="lbl">Addresses to remove</span><textarea id="ipgRemove" rows="3" maxlength="200000" spellcheck="false" aria-label="Addresses to remove">${E(z.remove)}</textarea></label>` : ''}</div>
        <div class="df-hint">IPv4 addresses, CIDR blocks (10.1.0.0/16) or ranges (10.1.1.1-10.1.1.9), one per line or comma separated.</div>`;
    } else if (z.act === 'delete') {
      body = `${table(E, src.concat(dst), 'ipgDel', z.del, g => `${g.kind}:${g.id}`)}
        <div class="df-hint">A group a rule uses cannot be deleted. You type DELETE and the group's name to confirm; Undo creates it again (with a new id). ${E(res.note || '')}</div>
        ${(res.not_checked || []).length ? `<div class="bp-card warn"><div class="t">Not checked</div><div>Not in scope, so a delete stays blocked until ticked: ${E(res.not_checked.join(', '))}.</div></div>` : ''}`;
    } else {
      body = `<div class="op-row"><button type="button" class="rp-btn" id="ipgExport">Save the groups as CSV</button>
          <label class="df-ctl"><span class="lbl">Open a CSV file</span><input id="ipgFile" type="file" accept=".csv,text/csv" aria-label="Open a CSV file of IP groups"></label></div>
        <div class="op-row"><label class="df-ctl"><span class="lbl">CSV to import</span><textarea id="ipgCsv" rows="6" maxlength="1048576" spellcheck="false" aria-label="CSV of IP groups to import">${E(z.csv)}</textarea></label></div>
        <div class="op-row"><fieldset class="op-inline"><legend>For a group that exists</legend>
          <label><input type="radio" name="ipgMode" value="merge"${z.mode === 'merge' ? ' checked' : ''}> Merge: add what is missing</label>
          <label><input type="radio" name="ipgMode" value="replace"${z.mode === 'replace' ? ' checked' : ''}> Replace: make its list exactly the CSV's</label></fieldset></div>
        <div class="df-hint">Columns: ${E((res.csv_columns || []).join(', '))}. Addresses are separated by ; within a cell, or one row per address. Groups not in the CSV are not touched.</div>`;
    }
    where.innerHTML = `${errs.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${errs.map(([k, v]) => `<li>${E(k)}: ${E(v)}</li>`).join('')}</ul></div>` : ''}
      <div class="op-row"><fieldset class="op-inline"><legend>What to do</legend>
        <label><input type="radio" name="ipgAct" value="source_edit"${z.act === 'source_edit' ? ' checked' : ''}> Edit an IP source group</label>
        <label><input type="radio" name="ipgAct" value="delete"${z.act === 'delete' ? ' checked' : ''}> Delete a group</label>
        <label><input type="radio" name="ipgAct" value="import"${z.act === 'import' ? ' checked' : ''}> Import or export CSV</label></fieldset></div>${body}`;
    const again = id => { render(res, where, S, H); const el = document.getElementById(id) || where.querySelector(`input[name="${id}"]:checked`); if (el) el.focus(); };
    where.querySelectorAll('input[name="ipgAct"]').forEach(r => r.addEventListener('change', () => { z.act = r.value; again('ipgAct'); }));
    where.querySelectorAll('input[name="ipgPick"]').forEach(r => r.addEventListener('change', () => { z.pick = r.value; again('ipgPick'); }));
    where.querySelectorAll('input[name="ipgDel"]').forEach(r => r.addEventListener('change', () => { z.del = r.value; }));
    where.querySelectorAll('input[name="ipgMode"]').forEach(r => r.addEventListener('change', () => { z.mode = r.value; }));
    [['ipgNewName', 'newName'], ['ipgNewDesc', 'newDesc'], ['ipgAdd', 'add'], ['ipgRemove', 'remove'], ['ipgCsv', 'csv']].forEach(([id, k]) => {
      const el = document.getElementById(id); if (el) el.addEventListener('input', () => { z[k] = el.value; });
    });
    const ex = document.getElementById('ipgExport');
    if (ex) ex.addEventListener('click', () => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([res.csv || ''], { type: 'text/csv;charset=utf-8' }));
      a.download = 'ip-groups.csv';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      H.say('Saved ip-groups.csv.');
    });
    const f = document.getElementById('ipgFile');
    if (f) f.addEventListener('change', () => {
      const file = f.files && f.files[0];
      if (!file) return;
      if (file.size > MAX) { H.say('That file is larger than 1 MB: split it.'); f.value = ''; return; }
      file.text().then(t => { z.csv = t; const ta = document.getElementById('ipgCsv'); if (ta) ta.value = t; H.say(`Read ${file.name}.`); })
        .catch(() => H.say('The file could not be read.'));
    });
  }
  function spec(S) {
    const z = st(S);
    if (z.act === 'source_edit') {
      if (z.pick === '') {
        if (!z.newName.trim()) throw new Error('Name the new group, or pick one.');
        return { type: 'ip_group_admin', action: 'source_edit', group: { new: z.newName.trim(), description: z.newDesc.trim() }, add: lines(z.add) };
      }
      return { type: 'ip_group_admin', action: 'source_edit', group: { id: z.pick }, add: lines(z.add), remove: lines(z.remove) };
    }
    if (z.act === 'delete') {
      if (!z.del) throw new Error('Pick the group to delete.');
      const [kind, id] = z.del.split(':');
      return { type: 'ip_group_admin', action: 'delete', kind, id };
    }
    if (!z.csv.trim()) throw new Error('Paste the CSV or open a CSV file.');
    if (z.csv.length > MAX) throw new Error('The CSV is larger than 1 MB: split it.');
    return { type: 'ip_group_admin', action: 'import', mode: z.mode, csv: z.csv };
  }
  window.OPS_PLUGINS.register({ type: 'ip_group_admin', render, spec });
}());
