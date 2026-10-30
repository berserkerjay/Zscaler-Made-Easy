/* Rules from a spreadsheet on Bulk changes (/report/operations): export ZIA
   Cloud Firewall, URL filtering or ZPA access policy rules as CSV, edit the
   file offline, then import it (ops_rule_csv.py on the shared engine).
   Choosing a file only checks it (POST /api/rule-csv/validate, no tenant
   read); nothing is planned until Preview and nothing is written until the
   page's Apply, with its gates. Deletes happen only when "Remove rules not
   in the file" is ticked, and then need the typed DELETE <n> RULES. */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;
  const MAX_BYTES = 1000000;

  function st(S) {
    if (!S.rcsv) S.rcsv = { policy: '', text: '', file: '', check: null, remove: false, enabled: false };
    return S.rcsv;
  }
  function errs(H, res) {
    const rows = Object.entries((res && res.errors) || {});
    return rows.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${rows.map(([k, v]) => `<li>${H.E(k)}: ${H.E(v)}</li>`).join('')}</ul></div>` : '';
  }
  function checkHtml(H, c) {
    if (!c) return '<div class="df-hint">No file chosen yet.</div>';
    if (c.busy) return '<div class="df-hint">Checking the file…</div>';
    if (c.ok) {
      return `<div class="bp-card info" role="status"><div class="t">The file is valid: ${H.E(c.rows)} rule${c.rows === 1 ? '' : 's'}</div>
        <div>Columns it changes: ${H.E((c.columns || []).filter(x => x !== 'name').join(', ') || 'none besides the name')}. Columns it leaves out are kept as they are.
        Click <strong>Preview the change</strong> to see every add, update, move${c.remove ? ' and delete' : ''} before anything is written.</div></div>`;
    }
    return `<div class="bp-card risk" role="alert"><div class="t">The file cannot be used</div><div>${H.E(c.message || '')}</div>
      ${(c.problems || []).length ? `<ul>${c.problems.slice(0, 20).map(p => `<li>Line ${H.E(p.line)}${p.column ? `, ${H.E(p.column)}` : ''}: ${H.E(p.message)}</li>`).join('')}</ul>` : ''}</div>`;
  }
  function columnsHtml(H, docs, policy) {
    const d = docs && docs.policies && docs.policies[policy];
    if (!d) return '';
    return `<details class="pa-details" id="rcCols"><summary>The columns of a ${H.E(d.label)} file</summary>
      <p class="df-hint">${H.E(docs.format)} At most ${H.E(docs.limits.rows)} rules and ${H.E(Math.round(docs.limits.bytes / 1000))} kB per file. A blank list or text cell empties it; a blank order, rank, state, action or true/false cell keeps the rule's value.</p>
      <div class="df-tablewrap"><table class="df-table"><caption class="sr-only">Columns of the file</caption><thead><tr><th scope="col">Column</th><th scope="col">What it holds</th></tr></thead>
      <tbody>${d.columns.map(c => `<tr><td><code>${H.E(c.name)}</code></td><td>${H.E(c.help)}</td></tr>`).join('')}</tbody></table></div></details>`;
  }
  function download(text, name) {
    const blob = new Blob(['﻿' + text], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name || 'rules.csv';
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  function render(res, where, S, H) {
    const E = H.E, z = st(S);
    const pols = (res.policies || []);
    const usable = pols.filter(p => p.in_scope && typeof p.csv === 'string');
    if (!usable.some(p => p.policy === z.policy)) { z.policy = usable.length ? usable[0].policy : ''; z.check = null; }
    const cur = usable.find(p => p.policy === z.policy);
    where.innerHTML = `${errs(H, res)}
      ${pols.filter(p => !p.in_scope).map(p => `<div class="df-hint">${E(p.label)}: ${E(p.why || 'not in scope')}</div>`).join('')}
      ${usable.length ? `<h3 class="op-h">1. Policy</h3>
      <fieldset class="op-inline"><legend class="sr-only">Policy</legend>${usable.map(p => `<label><input type="radio" name="rcPolicy" value="${E(p.policy)}"${p.policy === z.policy ? ' checked' : ''}> ${E(p.label)} (${E(p.rules)} rule${p.rules === 1 ? '' : 's'})</label>`).join(' ')}</fieldset>
      <h3 class="op-h">2. Export</h3>
      <div class="op-row"><button type="button" class="rp-btn" id="rcExport">Download the rules as CSV</button>
        <span class="df-hint">Names, not ids; the order and the admin rank; every cell safe to open in a spreadsheet.${cur && cur.truncated ? ' Only the first rules were exported: the policy is very large.' : ''}</span></div>
      ${columnsHtml(H, res.docs, z.policy)}
      <h3 class="op-h">3. Import the edited file</h3>
      <div class="op-row"><label class="df-ctl"><span class="lbl">CSV file</span><input type="file" id="rcFile" accept=".csv,text/csv" aria-describedby="rcFileHint"></label>
        <span class="df-hint" id="rcFileHint">Choosing a file only checks it. Nothing is read from or written to the tenant until you preview and apply.</span></div>
      <div id="rcCheck" aria-live="polite">${checkHtml(H, z.check)}</div>
      <div class="op-row"><label class="df-ctl"><input type="checkbox" id="rcRemove"${z.remove ? ' checked' : ''}><span>Remove rules not in the file</span></label>
        <span class="df-hint">Off by default. When ticked, every rule of the policy that is not in the file is deleted (never the Default, predefined or read-only rules), and applying needs the typed confirmation <strong>DELETE &lt;n&gt; RULES</strong>.</span></div>
      <div class="op-row"><label class="df-ctl"><input type="checkbox" id="rcEnabled"${z.enabled ? ' checked' : ''}><span>Create new rules enabled</span></label>
        <span class="df-hint">${z.policy === 'zpa_access' ? 'ZPA access rules cannot be created disabled, so new rows are left out unless you tick this (they take effect at once).' : 'Off by default: new ZIA rules are created disabled, so nothing changes for users until you turn them on.'}</span></div>
      <div class="df-hint">4. Click Preview the change below. 5. Apply needs write mode, your permission to change the tenant, the assessor's name and your confirmation.</div>`
      : '<div class="df-hint">No policy this operation handles is in scope on the Scope page.</div>'}`;
    where.querySelectorAll('input[name="rcPolicy"]').forEach(r => r.addEventListener('change', () => {
      z.policy = r.value; z.check = null; z.text = ''; z.file = '';
      render(res, where, S, H); const again = where.querySelector('input[name="rcPolicy"]:checked'); if (again) again.focus();
    }));
    const ex = document.getElementById('rcExport');
    if (ex) ex.addEventListener('click', () => { if (cur) { download(cur.csv, cur.filename); H.say(`${cur.label} rules downloaded as CSV.`); } });
    const rm = document.getElementById('rcRemove');
    if (rm) rm.addEventListener('change', e => { z.remove = e.target.checked; if (z.check && z.check.ok) { z.check.remove = z.remove; document.getElementById('rcCheck').innerHTML = checkHtml(H, z.check); } });
    const en = document.getElementById('rcEnabled');
    if (en) en.addEventListener('change', e => { z.enabled = e.target.checked; });
    const f = document.getElementById('rcFile');
    if (f) f.addEventListener('change', () => {
      const file = f.files && f.files[0];
      z.text = ''; z.file = ''; z.check = null;
      const box = document.getElementById('rcCheck');
      if (!file) { box.innerHTML = checkHtml(H, null); return; }
      if (file.size > MAX_BYTES) { z.check = { ok: false, message: `The file is larger than ${MAX_BYTES / 1000} kB; split it.` }; box.innerHTML = checkHtml(H, z.check); return; }
      z.check = { busy: true }; box.innerHTML = checkHtml(H, z.check);
      const reader = new FileReader();
      reader.onerror = () => { z.check = { ok: false, message: 'The file could not be read.' }; box.innerHTML = checkHtml(H, z.check); };
      reader.onload = async () => {
        const text = String(reader.result || '');
        try {
          const r = await fetch('/api/rule-csv/validate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ policy: z.policy, csv: text }) });
          const d = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error((d && d.detail) || `HTTP ${r.status}`);
          z.check = Object.assign(d, { remove: z.remove });
          if (d.ok) { z.text = text; z.file = file.name; }
        } catch (e) { z.check = { ok: false, message: e.message }; }
        box.innerHTML = checkHtml(H, z.check);
        H.say(z.check.ok ? `The file is valid: ${z.check.rows} rules. Preview next.` : 'The file cannot be used; see the problems listed.');
      };
      reader.readAsText(file, 'utf-8');
    });
  }
  function spec(S) {
    const z = st(S);
    if (!z.policy) throw new Error('No policy is in scope.');
    if (!z.text) throw new Error(z.check && !z.check.ok ? 'The file cannot be used: fix the problems listed, then choose it again.' : 'Choose the edited CSV file first.');
    const type = z.policy === 'zpa_access' ? 'zpa_access_csv' : 'zia_rules_csv';
    return { type, policy: z.policy, csv: z.text, remove_missing: !!z.remove, new_rules_enabled: !!z.enabled };
  }

  window.OPS_PLUGINS.register({ type: 'zia_rules_csv', render, spec: S => spec(S) });
  window.OPS_PLUGINS.register({ type: 'zpa_access_csv', render, spec: S => spec(S) });
})();
