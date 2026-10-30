/* The rule editor on Bulk changes (/report/operations, "Build new"), four
   forms on the shared engine (ops_rule_editor.py, ops_zia_objects.py):
     rule_edit         create, edit, duplicate or delete one ZIA rule, with a
                       form per rule type (only the fields the SDK model has),
                       pickers by name, placement and a plain-language preview;
     zpa_segment_edit  edit one ZPA application segment, enable or disable it;
     app_object_edit   cloud app instances and tenancy restriction profiles;
     proxy_chain_edit  proxies for proxy chaining, the gateways that use them
                       and the portal steps a gateway needs.
   The page does the rest: Read from the tenant, Preview, the gates, Apply, Undo.
   Every value from the tenant is escaped (H.E) before it is shown. */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;

  function st(S) {
    if (!S.re) S.re = { policy: '', mode: 'create', rule: '', cacType: 'WEBMAIL', values: null, place: 'bottom', placeOrder: 1, placeBelow: '',
      enabled: false, state: '', dupName: '', filter: '', seg: '', obj: 'instance', objMode: 'create', objId: '', objValues: null };
    return S.re;
  }
  function errs(H, res) {
    const rows = Object.entries((res && res.errors) || {});
    return rows.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${rows.map(([k, v]) => `<li>${H.E(k)}: ${H.E(v)}</li>`).join('')}</ul></div>` : '';
  }
  const LISTS = ['addrs', 'countries', 'enums_free', 'cac_actions', 'lines', 'identifiers'];
  function hint(f, nameMax) {
    const req = f.required ? 'Required. ' : 'Optional. ';
    switch (f.kind) {
      case 'text': return `${req}Up to ${nameMax || 255} characters, no angle brackets or control characters.`;
      case 'longtext': return `${req}Up to 255 bytes of plain text.`;
      case 'enum': case 'ssl_action': return `${req}Pick one.`;
      case 'enums': return `${req}Tick any; none means every one.`;
      case 'refs': case 'names': return `${req}Pick one or more by name (Ctrl or Cmd picks several); none means any.`;
      case 'ref': return `${req}Pick one by name.`;
      case 'addrs': return `${req}One per line: an IP address, a range like 10.0.0.1-10.0.0.9, a CIDR block like 10.0.0.0/8${f.ip_only ? '' : ', or a domain such as example.com or *.example.com'}.`;
      case 'countries': return `${req}One per line: a two-letter code such as US, or COUNTRY_US.`;
      case 'enums_free': return `${req}One per line: Zscaler's names, such as FTCATEGORY_ZIP.`;
      case 'cac_actions': return `${req}One per line, such as BLOCK_FILE_SHARE_UPLOAD; ZIA refuses an action the application does not support.`;
      case 'bool': case 'flag01': return 'Tick for yes.';
      case 'int': return `${req}A whole number${f.min != null && f.max != null ? ` from ${f.min} to ${f.max}` : ''}.`;
      case 'ports': return 'Optional. Ports and ranges, separated by commas: 443, 8000-8080.';
      case 'lines': return `${req}One per line, no spaces.`;
      case 'identifiers': return `${req}One per line: URL, REFURL or KEYWORD, a space, then the value (URL acme.sharepoint.com).`;
      case 'host': return `${req}An IP address or a host name such as proxy.example.com.`;
      default: return req;
    }
  }
  // One field's control; its accessible name is the field's label.
  function control(H, f, val, refs) {
    const E = H.E, id = `reF_${E(f.key)}" data-re-kind="${E(f.kind)}`, lab = E(f.label);
    const v = val == null ? (f.default != null ? f.default : '') : val;
    if (f.kind === 'text') return `<input id="${id}" value="${E(v)}" maxlength="255" aria-label="${lab}">`;
    if (f.kind === 'host') return `<input id="${id}" value="${E(v)}" maxlength="253" aria-label="${lab}">`;
    if (f.kind === 'longtext') return `<textarea id="${id}" rows="2" aria-label="${lab}">${E(v)}</textarea>`;
    if (f.kind === 'int') return `<input id="${id}" type="number" inputmode="numeric" value="${E(v)}"${f.min != null ? ` min="${E(f.min)}"` : ''}${f.max != null ? ` max="${E(f.max)}"` : ''} aria-label="${lab}">`;
    if (f.kind === 'bool' || f.kind === 'flag01') return `<input id="${id}" type="checkbox"${v === true ? ' checked' : ''} aria-label="${lab}">`;
    if (f.kind === 'enum' || f.kind === 'ssl_action') {
      return `<select id="${id}" aria-label="${lab}">${f.required ? '' : '<option value="">(not set)</option>'}${(f.values || []).map(x => `<option value="${E(x)}"${x === v ? ' selected' : ''}>${E(x.replace(/_/g, ' ').toLowerCase())}</option>`).join('')}</select>`;
    }
    if (f.kind === 'enums') {
      const on = new Set(Array.isArray(v) ? v : []);
      return `<fieldset class="op-inline" id="${id}"><legend class="sr-only">${lab}</legend>${(f.values || []).map(x => `<label><input type="checkbox" name="reE_${E(f.key)}" data-re-kind="enums" value="${E(x)}"${on.has(x) ? ' checked' : ''}> ${E(x.replace(/_/g, ' ').toLowerCase())}</label>`).join(' ')}</fieldset>`;
    }
    if (f.kind === 'refs' || f.kind === 'names' || f.kind === 'ref') {
      const r = (refs || {})[f.ref] || { rows: [] }, picked = new Set((Array.isArray(v) ? v : (v ? [v] : [])).map(String));
      const known = new Set(r.rows.map(x => String(x.value)));
      const extra = [...picked].filter(x => !known.has(x)).map(x => ({ value: x, name: `${f.kind === 'names' ? x : '#' + x} (not in the list read)` }));
      const opts = r.rows.concat(extra).map(x => `<option value="${E(x.value)}"${picked.has(String(x.value)) ? ' selected' : ''}>${E(x.name)}${x.note ? ` — ${E(x.note)}` : ''}</option>`).join('');
      const multi = f.kind !== 'ref';
      return `<select id="${id}"${multi ? ` multiple size="${Math.min(6, Math.max(2, r.rows.length + extra.length))}"` : ''} aria-label="${lab}">${multi ? '' : '<option value="">(none)</option>'}${opts}</select>${r.truncated ? '<div class="df-hint">Only the first rows of a long list are shown.</div>' : ''}${r.not_in_scope ? '<div class="df-hint">Not in scope: tick ZIA platform on the Scope page to pick these.</div>' : r.error ? `<div class="df-hint">The list could not be read: ${E(r.error)}</div>` : ''}`;
    }
    if (LISTS.includes(f.kind) || f.kind === 'ports') {
      const text = Array.isArray(v) ? v.join(f.kind === 'ports' ? ', ' : '\n') : String(v || '');
      return f.kind === 'ports' ? `<input id="${id}" value="${E(text)}" aria-label="${lab}">` : `<textarea id="${id}" rows="3" aria-label="${lab}">${E(text)}</textarea>`;
    }
    return '';
  }
  function collect(fields) {
    const out = {};
    fields.forEach(f => {
      const el = document.getElementById(`reF_${f.key}`);
      if (!el) return;
      if (f.kind === 'bool' || f.kind === 'flag01') out[f.key] = el.checked;
      else if (f.kind === 'enums') out[f.key] = [...el.querySelectorAll('input:checked')].map(x => x.value);
      else if (f.kind === 'refs' || f.kind === 'names') out[f.key] = [...el.selectedOptions].map(o => o.value);
      else if (f.kind === 'ports') out[f.key] = el.value.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
      else if (LISTS.includes(f.kind)) out[f.key] = el.value.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
      else if (f.kind === 'int') out[f.key] = el.value === '' ? null : Number(el.value);
      else out[f.key] = el.value;
    });
    return out;
  }
  function formTable(H, fields, values, refs, nameMax, caption) {
    return `<div class="df-tablewrap"><table class="df-table op-form"><caption class="sr-only">${H.E(caption)}</caption>
      <thead><tr><th scope="col">Field</th><th scope="col">Value</th><th scope="col">What it takes</th></tr></thead>
      <tbody>${fields.map(f => `<tr><th scope="row"><label for="reF_${H.E(f.key)}">${H.E(f.label)}</label>${f.required ? ' <span class="df-by">required</span>' : ''}</th>
        <td>${control(H, f, (values || {})[f.key], refs)}</td><td class="df-hint">${H.E(hint(f, nameMax))}</td></tr>`).join('')}</tbody></table></div>`;
  }

  // ── Edit a rule ──
  function rulesOf(res, policy) { return ((res.policies || []).find(p => p.policy === policy) || { rules: [] }).rules; }
  function renderRule(res, where, S, H) {
    const E = H.E, z = st(S), forms = res.forms || {}, order = res.order || Object.keys(forms);
    if (!order.length) { where.innerHTML = `${errs(H, res)}<div class="df-hint">No rule type the editor changes is in scope on the Scope page.</div>`; return; }
    if (!forms[z.policy]) { z.policy = order[0]; z.values = null; z.rule = ''; }
    const form = forms[z.policy], rules = rulesOf(res, z.policy);
    const rule = rules.find(r => String(r.id) === String(z.rule));
    if (z.mode !== 'create' && !rule) z.rule = '';
    if (z.values === null) z.values = z.mode === 'update' && rule ? Object.assign({}, rule.values) : {};
    const ar = res.admin_rank || {};
    const f = z.filter.toLowerCase();
    const shown = rules.filter(r => !f || r.name.toLowerCase().includes(f));
    const ruleOpts = shown.map(r => `<option value="${E(r.id)}"${String(r.id) === String(z.rule) ? ' selected' : ''}>${E(r.order)}. ${E(r.name)}${r.rule_type ? ` (${E(r.rule_type)})` : ''} · ${E(String(r.state).toLowerCase())}${r.rank != null ? ` · rank ${E(r.rank)}` : ''}${r.locked ? ' · not changed here' : ''}</option>`).join('');
    const live = rules.filter(r => !r.default);
    const modes = [['create', 'Create a rule'], ['update', 'Edit a rule'], ['duplicate', 'Duplicate a rule'], ['delete', 'Delete a rule']];
    let body = '';
    if (z.mode !== 'create') {
      body += `<div class="op-row"><label class="df-ctl"><span class="lbl">Find a rule</span><input id="reFilter" type="search" value="${E(z.filter)}" aria-label="Find a rule by name"></label>
        <label class="df-ctl"><span class="lbl">Rule</span><select id="reRule" aria-label="The rule to ${E(z.mode === 'update' ? 'edit' : z.mode)}"><option value="">Pick a rule…</option>${ruleOpts}</select></label></div>`;
      if (rule && rule.locked) body += `<div class="bp-card warn"><div class="t">Not changed here</div><div>${E(rule.locked)}</div></div>`;
    } else if (z.policy === 'cloud_app_control') {
      body += `<div class="op-row"><label class="df-ctl"><span class="lbl">Application type</span><select id="reCacType" aria-label="Cloud App Control application type">${(res.cac_types || []).map(t => `<option value="${E(t)}"${t === z.cacType ? ' selected' : ''}>${E(t.replace(/_/g, ' ').toLowerCase())}</option>`).join('')}</select></label></div>`;
    }
    if (z.mode === 'create' || (z.mode === 'update' && rule && !rule.locked)) {
      body += formTable(H, form.fields, z.values, res.refs, form.name_max, `${form.label} rule fields`);
    }
    if (z.mode === 'create') {
      body += `<h3 class="op-h">Placement</h3><div class="op-row">
        <label class="df-ctl"><span class="lbl">Place it</span><select id="rePlace" aria-label="Where to place the new rule">
          ${[['bottom', 'At the bottom (above the Default rule)'], ['top', 'At the top (order 1)'], ['order', 'At an order number'], ['below', 'Right below a rule']].map(([v, l]) => `<option value="${E(v)}"${z.place === v ? ' selected' : ''}>${E(l)}</option>`).join('')}</select></label>
        ${z.place === 'order' ? `<label class="df-ctl"><span class="lbl">Order</span><input id="rePlaceOrder" type="number" min="1" max="${E(live.length + 1)}" value="${E(z.placeOrder)}" aria-label="Order number for the new rule"></label>` : ''}
        ${z.place === 'below' ? `<label class="df-ctl"><span class="lbl">Below</span><select id="rePlaceBelow" aria-label="The rule to place it below"><option value="">Pick a rule…</option>${live.map(r => `<option value="${E(r.id)}"${String(r.id) === String(z.placeBelow) ? ' selected' : ''}>${E(r.order)}. ${E(r.name)}</option>`).join('')}</select></label>` : ''}</div>
        <div class="df-hint">${E(ar.describe || '')}</div>
        <div class="op-row"><label class="df-ctl"><input type="checkbox" id="reEnabled"${z.enabled ? ' checked' : ''}><span>Create it enabled (off by default: the rule changes nothing until you enable it)</span></label></div>`;
    }
    if (z.mode === 'update' && rule && !rule.locked) {
      body += `<div class="op-row"><label class="df-ctl"><span class="lbl">State</span><select id="reState" aria-label="The rule's state after the change">
        <option value="">Keep it ${E(String(rule.state).toLowerCase())}</option><option value="ENABLED"${z.state === 'ENABLED' ? ' selected' : ''}>Enable it</option><option value="DISABLED"${z.state === 'DISABLED' ? ' selected' : ''}>Disable it</option></select></label></div>`;
    }
    if (z.mode === 'duplicate' && rule) {
      body += `<div class="op-row"><label class="df-ctl"><span class="lbl">Name of the copy</span><input id="reDupName" value="${E(z.dupName || ('Copy of ' + rule.name).slice(0, form.name_max))}" maxlength="${E(form.name_max)}" aria-label="Name of the copy"></label></div>
        <div class="df-hint">The copy has every setting of '${E(rule.name)}', sits right below it at its rank, and is created disabled.</div>`;
    }
    if (z.mode === 'delete' && rule && !rule.locked) {
      body += `<div class="bp-card warn"><div class="t">Deleting '${E(rule.name)}'</div><div>You type DELETE and the rule's name to confirm when you apply. Undo re-creates it with the same settings, order, rank and state.</div></div>`;
    }
    where.innerHTML = `${errs(H, res)}
      <p class="df-hint">Pick the rule type and what to do. The form shows only the fields this rule type takes; the preview says in one sentence what the rule will do, where it goes and its rank. Nothing is written until you apply.</p>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Rule type</span><select id="reType" aria-label="Rule type">${order.map(p => `<option value="${E(p)}"${p === z.policy ? ' selected' : ''}>${E(forms[p].label)} (${E(rulesOf(res, p).length)})</option>`).join('')}</select></label></div>
      <div class="op-row"><fieldset class="op-inline"><legend>What to do</legend>${modes.map(([v, l]) => `<label><input type="radio" name="reMode" value="${E(v)}"${z.mode === v ? ' checked' : ''}> ${E(l)}</label>`).join(' ')}</fieldset></div>
      ${body}`;
    const again = id => { renderRule(res, where, S, H); const el = document.getElementById(id) || where.querySelector(`input[name="${id}"]:checked`); if (el) el.focus(); };
    const keep = () => { if (z.mode === 'create' || z.mode === 'update') z.values = Object.assign({}, z.values, collect(form.fields)); };
    document.getElementById('reType').addEventListener('change', e => { z.policy = e.target.value; z.values = null; z.rule = ''; again('reType'); });
    where.querySelectorAll('input[name="reMode"]').forEach(r => r.addEventListener('change', () => { z.mode = r.value; z.values = null; again('reMode'); }));
    const on = (id, ev, fn) => { const el = document.getElementById(id); if (el) el.addEventListener(ev, fn); };
    on('reRule', 'change', e => { z.rule = e.target.value; z.values = null; z.dupName = ''; again('reRule'); });
    on('reFilter', 'input', e => { z.filter = e.target.value; const pos = e.target.selectionStart; again('reFilter'); try { document.getElementById('reFilter').setSelectionRange(pos, pos); } catch (x) { /* search */ } });
    on('reCacType', 'change', e => { z.cacType = e.target.value; });
    on('rePlace', 'change', e => { keep(); z.place = e.target.value; again('rePlace'); });
    on('rePlaceOrder', 'input', e => { z.placeOrder = e.target.value; });
    on('rePlaceBelow', 'change', e => { z.placeBelow = e.target.value; });
    on('reEnabled', 'change', e => { z.enabled = e.target.checked; });
    on('reState', 'change', e => { z.state = e.target.value; });
    on('reDupName', 'input', e => { z.dupName = e.target.value; });
    S.reForm = { res, form, rule };
  }
  function specRule(S) {
    const z = st(S), ctx = S.reForm || {};
    if (!ctx.form) throw new Error('Read from the tenant first.');
    const base = { type: 'rule_edit', action: z.mode, policy: z.policy };
    if (z.mode === 'create') {
      const spec = Object.assign(base, { fields: collect(ctx.form.fields), enabled: !!z.enabled, place: { at: z.place } });
      if (z.policy === 'cloud_app_control') spec.rule_type = z.cacType;
      if (z.place === 'order') spec.place.order = Number(z.placeOrder);
      if (z.place === 'below') { if (!z.placeBelow) throw new Error('Pick the rule to place it below.'); spec.place.id = z.placeBelow; }
      return spec;
    }
    const r = ctx.rule;
    if (!r) throw new Error('Pick the rule.');
    if (r.locked && z.mode !== 'duplicate') throw new Error(`This rule is not changed here: ${r.locked}`);
    Object.assign(base, { id: r.id, rule_type: r.rule_type || '' });
    if (z.mode === 'update') { base.fields = collect(ctx.form.fields); if (z.state) base.state = z.state; }
    if (z.mode === 'duplicate') base.name = (document.getElementById('reDupName') || {}).value || '';
    if (z.mode === 'delete') base.name = r.name;
    return base;
  }
  function planRule(p, where, H) {
    const E = H.E, box = document.createElement('div');
    box.innerHTML = `${(p.summary || []).length ? `<div class="bp-card info" role="note"><div class="t">What this does</div>${p.summary.map(s => `<p>${E(s)}</p>`).join('')}</div>` : ''}
      ${(p.fields_table || []).length ? `<h3 class="op-h">The rule's fields</h3><div class="df-tablewrap"><table class="df-table"><caption class="sr-only">The rule's fields before and after</caption>
        <thead><tr><th scope="col">Field</th><th scope="col">Before</th><th scope="col">After</th></tr></thead>
        <tbody>${p.fields_table.map(r => `<tr><td>${E(r.field)}</td><td>${E(r.before)}</td><td>${E(r.after)}</td></tr>`).join('')}</tbody></table></div>` : ''}`;
    const after = where.querySelector('.op-summary + .df-hint') || where.querySelector('.op-summary');
    if (after) after.after(box); else where.appendChild(box);
  }

  // ── Objects: ZPA segments, cloud app instances and tenancy profiles, proxies ──
  function renderObjects(kinds, type) {
    return function (res, where, S, H) {
      const E = H.E, z = st(S), forms = res.forms || {};
      const many = kinds.length > 1;
      if (z.objType !== type) { z.objType = type; z.obj = kinds[0]; z.objId = ''; z.objValues = null; z.objMode = 'create'; }
      if (!kinds.includes(z.obj)) z.obj = kinds[0];
      const form = forms[z.obj];
      if (!form) { where.innerHTML = `${errs(H, res)}<div class="df-hint">Read from the tenant to load the form.</div>`; return; }
      const list = (res.objects || {})[z.obj] || [];
      const canCreate = z.obj !== 'segment';
      if (!canCreate) z.objMode = 'update';
      const cur = list.find(o => String(o.id) === String(z.objId));
      if (z.objValues === null) z.objValues = z.objMode === 'update' && cur ? Object.assign({}, cur.values) : {};
      const browse = `<div class="df-tablewrap"><table class="df-table"><caption class="sr-only">${E(form.label)}s in the tenant</caption>
        <thead><tr><th scope="col">Name</th>${form.fields.filter(f => f.key !== 'name' && !/_name$/.test(f.key)).slice(0, 3).map(f => `<th scope="col">${E(f.label.split(' (')[0])}</th>`).join('')}</tr></thead>
        <tbody>${list.map(o => `<tr><td>${E(o.name)}${o.domains && o.domains.length ? `<div class="df-by">${E(o.domains.slice(0, 4).join(', '))}</div>` : ''}</td>${form.fields.filter(f => f.key !== 'name' && !/_name$/.test(f.key)).slice(0, 3).map(f => { const v = o.values[f.key]; return `<td>${E(Array.isArray(v) ? v.join(', ') : typeof v === 'boolean' ? (v ? 'yes' : 'no') : (v == null ? '' : v))}</td>`; }).join('')}</tr>`).join('') || `<tr><td colspan="4">None in the tenant yet.</td></tr>`}</tbody></table></div>`;
      const gw = res.gateway_report;
      const gwHtml = gw ? `<h3 class="op-h">Proxy gateways</h3><div class="df-tablewrap"><table class="df-table"><caption class="sr-only">Proxy gateways</caption>
          <thead><tr><th scope="col">Gateway</th><th scope="col">Primary proxy</th><th scope="col">Secondary proxy</th><th scope="col">Fail close</th></tr></thead>
          <tbody>${(gw.gateways || []).map(g => `<tr><td>${E(g.name)}</td><td>${E(g.primary)}</td><td>${E(g.secondary)}</td><td>${g.fail_closed ? 'on' : 'off'}</td></tr>`).join('') || '<tr><td colspan="4">No proxy gateway yet.</td></tr>'}</tbody></table></div>
          <div class="df-hint">${E(gw.why_manual)}</div>` : '';
      where.innerHTML = `${errs(H, res)}
        ${many ? `<div class="op-row"><fieldset class="op-inline"><legend>Which objects</legend>${kinds.map(k => `<label><input type="radio" name="reObj" value="${E(k)}"${z.obj === k ? ' checked' : ''}> ${E(forms[k].label)}s</label>`).join(' ')}</fieldset></div>` : ''}
        <h3 class="op-h">${E(form.label)}s in the tenant (read-only)</h3>${browse}${gwHtml}
        <h3 class="op-h">${canCreate ? 'Create or edit one' : 'Edit one'}</h3>
        ${canCreate ? `<div class="op-row"><fieldset class="op-inline"><legend>What to do</legend><label><input type="radio" name="reObjMode" value="create"${z.objMode === 'create' ? ' checked' : ''}> Create one</label> <label><input type="radio" name="reObjMode" value="update"${z.objMode === 'update' ? ' checked' : ''}> Edit one</label></fieldset></div>` : ''}
        ${z.objMode === 'update' ? `<div class="op-row"><label class="df-ctl"><span class="lbl">${E(form.label)}</span><select id="reObjPick" aria-label="The ${E(form.label.toLowerCase())} to edit"><option value="">Pick one…</option>${list.map(o => `<option value="${E(o.id)}"${String(o.id) === String(z.objId) ? ' selected' : ''}>${E(o.name)}</option>`).join('')}</select></label></div>` : ''}
        ${z.objMode === 'create' || cur ? formTable(H, form.fields, z.objValues, {}, 255, `${form.label} fields`) : ''}`;
      const again = id => { renderObjects(kinds, type)(res, where, S, H); const el = document.getElementById(id) || where.querySelector(`input[name="${id}"]:checked`); if (el) el.focus(); };
      where.querySelectorAll('input[name="reObj"]').forEach(r => r.addEventListener('change', () => { z.obj = r.value; z.objId = ''; z.objValues = null; again('reObj'); }));
      where.querySelectorAll('input[name="reObjMode"]').forEach(r => r.addEventListener('change', () => { z.objMode = r.value; z.objValues = null; again('reObjMode'); }));
      const pick = document.getElementById('reObjPick');
      if (pick) pick.addEventListener('change', e => { z.objId = e.target.value; z.objValues = null; again('reObjPick'); });
      S.reObj = { form, cur, type };
    };
  }
  function specObject(S) {
    const z = st(S), ctx = S.reObj || {};
    if (!ctx.form) throw new Error('Read from the tenant first.');
    const spec = { type: ctx.type, action: z.objMode, object: z.obj, fields: collect(ctx.form.fields) };
    if (z.objMode === 'update') { if (!ctx.cur) throw new Error('Pick the one to edit.'); spec.id = ctx.cur.id; }
    return spec;
  }
  function stepsCard(H, gw) {
    return gw && (gw.manual_steps || []).length ? `<div class="bp-card warn" role="note"><div class="t">Steps in the ZIA Admin Portal (the API cannot do them)</div><ol>${gw.manual_steps.map(s => `<li>${H.E(s)}</li>`).join('')}</ol></div>` : '';
  }
  function planProxy(p, where, H) { const d = document.createElement('div'); d.innerHTML = stepsCard(H, p.gateway_report); where.appendChild(d); }

  window.OPS_PLUGINS.register({ type: 'rule_edit', render: renderRule, spec: S => specRule(S), plan: planRule });
  window.OPS_PLUGINS.register({ type: 'zpa_segment_edit', render: renderObjects(['segment'], 'zpa_segment_edit'), spec: S => specObject(S) });
  window.OPS_PLUGINS.register({ type: 'app_object_edit', render: renderObjects(['instance', 'tenancy'], 'app_object_edit'), spec: S => specObject(S) });
  window.OPS_PLUGINS.register({ type: 'proxy_chain_edit', render: renderObjects(['proxy'], 'proxy_chain_edit'), spec: S => specObject(S), plan: planProxy,
    result: (r, where, H) => { const d = document.createElement('div'); d.innerHTML = stepsCard(H, r.gateway_report); where.appendChild(d); } });
})();
