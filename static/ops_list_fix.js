/* Fix rows from Test a list, on Bulk changes (/report/operations).
   The form of the "list_fix" operation (ops_list_fix.py): the rows of the
   Path analyzer's Test a list that missed what was expected, handed off by
   Fix selected (?fix=<id>), one section per area and purpose: the IP
   destination group(s) to put them in (or take them out of), then the Cloud
   Firewall or DNS Control rule to add the group to, or a new rule (created
   disabled unless you tick it on), or the ATP allow or deny list. Without a
   hand-off, one section takes a pasted list. The page does the rest: Read
   from the tenant, Preview (each change in plain words, linked to the rows
   it fixes), the four gates, Apply, Undo. After an apply, Prove it tests
   the same rows again (the Test a list job) and says which now do what
   was expected. Nothing here writes. */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;
  const AREA = { firewall: 'Cloud Firewall', dns: 'DNS Control', atp: 'Advanced Threat Protection lists' };
  const RES = { blocked: 'Blocked', allowed: 'Allowed', bypassed: 'Bypassed', isolated: 'Isolated', caution: 'Caution', unverified: 'Unverified', 'not tested': 'Not tested' };
  const isIp = v => /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$|^\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}$/.test(v);
  const isV6 = v => v.includes(':') && /^[0-9a-f:.\/]+$/i.test(v);
  const today = () => new Date().toISOString().slice(0, 10);
  function errs(H, res) {
    const rows = Object.entries((res && res.errors) || {});
    return rows.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${rows.map(([k, v]) => `<li>${H.E(k)}: ${H.E(v)}</li>`).join('')}</ul></div>` : '';
  }

  function section(f) {
    const dests = (f.destinations || []).map(d => ({ value: String(d.value || ''), rows: (d.rows || []).slice(0, 50) }));
    const name = `${f.purpose === 'allow' ? 'Allow' : 'Block'} ${today()}`;
    return { area: f.area || 'firewall', purpose: f.purpose === 'allow' ? 'allow' : 'block', include: true, mode: 'add', dests,
      rows: f.rows || [], decided: f.decided_by || [], rec: f.recommendation || '',
      ip: 'new', ipName: `Fix ${name} IPs`, host: 'new', hostName: `Fix ${name} hosts`,
      rule: 'new', ruleId: '', ruleName: `Fix ${name}`.slice(0, 31), above: '', enabled: false, services: [] };
  }
  function st(S) {
    if (!S.lf) S.lf = { sections: null, manual: { area: 'firewall', purpose: 'block', text: '' }, rows: [] };
    const z = S.lf;
    if (z.sections === null && S.handoff && Array.isArray(S.handoff.fixes) && S.handoff.fixes.length) {
      z.sections = S.handoff.fixes.map(section);
      z.rows = S.handoff.rows || [];
    }
    return z;
  }
  const rowLinks = (H, rows) => (rows || []).slice(0, 12).map(n => `<a href="#lf-row-${H.E(n)}">${H.E(n)}</a>`).join(', ') + ((rows || []).length > 12 ? ` and ${rows.length - 12} more` : '');

  function groupSelect(H, res, i, which, sec) {
    const E = H.E, types = which === 'ip' ? ['DSTN_IP'] : ['DSTN_FQDN', 'DSTN_DOMAIN'];
    const groups = (res.ip_groups || []).filter(g => g.editable && types.includes(g.type));
    const word = which === 'ip' ? 'addresses' : 'host names';
    const cur = sec[which], nm = which === 'ip' ? sec.ipName : sec.hostName;
    return `<label class="df-ctl"><span class="lbl">${which === 'ip' ? 'Put the addresses in' : 'Put the host names in'}</span>
        <select id="lf${which === 'ip' ? 'Ip' : 'Host'}${i}" aria-label="IP destination group for the ${word}">
        ${sec.mode === 'add' ? `<option value="new"${cur === 'new' ? ' selected' : ''}>A new group…</option>` : ''}
        ${groups.map(g => `<option value="${E(g.id)}"${String(cur) === String(g.id) ? ' selected' : ''}>${E(g.name)} (${E(g.count)} of ${E((res.limits || {}).group_addresses || 8000)})</option>`).join('')}</select></label>
      ${cur === 'new' && sec.mode === 'add' ? `<label class="df-ctl"><span class="lbl">New group name</span><input id="lf${which === 'ip' ? 'Ip' : 'Host'}Name${i}" value="${E(nm)}" maxlength="128" aria-label="Name of the new group for the ${word}"></label>` : ''}`;
  }
  function ruleBlock(H, res, i, sec) {
    const E = H.E, rules = (res[`${sec.area}_rules`] || []);
    const fit = rules.filter(r => !r.locked && r.kind === sec.purpose);
    const svc = sec.area === 'firewall' ? `<label class="df-ctl"><span class="lbl">Network services (optional)</span><select id="lfSvc${i}" multiple size="3" aria-label="Network services to add to the rule">
        ${(res.services || []).map(s => `<option value="${E(s.id)}"${sec.services.includes(String(s.id)) ? ' selected' : ''}>${E(s.name)}</option>`).join('')}</select></label>` : '';
    const placeable = rules.filter(r => !r.locked);
    const decided = rules.find(r => sec.decided.includes(r.name) && !r.locked);
    if (sec.rule === 'new' && !sec.above && decided) sec.above = String(decided.id);
    return `<div class="op-row"><label class="df-ctl"><span class="lbl">Then</span><select id="lfRule${i}" aria-label="Which rule uses the group">
        <option value="none"${sec.rule === 'none' ? ' selected' : ''}>Only change the group(s)</option>
        <option value="new"${sec.rule === 'new' ? ' selected' : ''}>Create a new ${E(AREA[sec.area])} rule</option>
        <option value="existing"${sec.rule === 'existing' ? ' selected' : ''}>Add the group(s) to an existing rule</option></select></label>
      ${sec.rule === 'existing' ? `<label class="df-ctl"><span class="lbl">Rule (${sec.purpose === 'block' ? 'Block' : 'Allow'} rules only)</span><select id="lfRuleId${i}" aria-label="Existing rule to add the group to">
          <option value="">Pick one…</option>${fit.map(r => `<option value="${E(r.id)}"${String(sec.ruleId) === String(r.id) ? ' selected' : ''}>${E(r.order)}. ${E(r.name)} (${E(String(r.state || '').toLowerCase())})</option>`).join('')}</select></label>` : ''}
      ${sec.rule === 'new' ? `<label class="df-ctl"><span class="lbl">New rule name (at most 31 characters)</span><input id="lfRuleName${i}" value="${E(sec.ruleName)}" maxlength="31" aria-label="Name of the new rule"></label>
        <label class="df-ctl"><span class="lbl">Place it above</span><select id="lfAbove${i}" aria-label="Rule the new rule goes above">
          <option value="">Last (above the Default rule)</option>${placeable.map(r => `<option value="${E(r.id)}"${String(sec.above) === String(r.id) ? ' selected' : ''}>${E(r.order)}. ${E(r.name)}${sec.decided.includes(r.name) ? ' (decided these rows)' : ''}</option>`).join('')}</select></label>
        <label class="df-ctl"><input type="checkbox" id="lfOn${i}"${sec.enabled ? ' checked' : ''}><span>Create it enabled (off: it arrives disabled, to turn on after review)</span></label>` : ''}
      ${sec.rule !== 'none' ? svc : ''}</div>`;
  }
  function sectionHtml(H, res, i, sec) {
    const E = H.E, inScope = (res.areas || []).includes(sec.area);
    const ips = sec.dests.filter(d => isIp(d.value)), v6 = sec.dests.filter(d => isV6(d.value)), hosts = sec.dests.filter(d => !isIp(d.value) && !isV6(d.value));
    const head = `<h3 class="op-h">${E(AREA[sec.area])}: ${sec.dests.length} destination${sec.dests.length === 1 ? '' : 's'} to ${E(sec.purpose)}${sec.rows.length ? ` <span class="df-by">rows ${rowLinks(H, sec.rows)}</span>` : ''}</h3>`;
    if (!inScope) return `${head}<div class="bp-card warn"><div>${E((res.not_in_scope_areas || {})[sec.area] || 'Not in scope on the Scope page.')}</div></div>`;
    const inc = `<label class="df-ctl"><input type="checkbox" id="lfInc${i}"${sec.include ? ' checked' : ''}><span>Include this fix</span></label>`;
    const rec = sec.rec ? `<div class="df-hint">${E(sec.rec)}</div>` : '';
    const list = `<details class="pa-details"><summary>The destinations (${sec.dests.length})</summary><ul class="op-checks">${sec.dests.slice(0, 500).map(d => `<li>${E(d.value)}${d.rows.length ? ` <span class="df-by">row ${rowLinks(H, d.rows)}</span>` : ''}</li>`).join('')}</ul></details>`;
    if (sec.area === 'atp') {
      const lists = res.atp_lists || {};
      const addTo = sec.purpose === 'block' ? 'denylist' : 'allowlist', other = sec.purpose === 'block' ? 'allowlist' : 'denylist';
      return `${head}${rec}<div class="op-row">${inc}<label class="df-ctl"><span class="lbl">Change</span><select id="lfAct${i}" aria-label="How the ATP lists change">
          <option value="add"${sec.mode === 'add' ? ' selected' : ''}>Add them to the security policy ${addTo} (${E((lists[addTo] || {}).count || 0)} entries now)</option>
          <option value="remove"${sec.mode === 'remove' ? ' selected' : ''}>Take them off the security policy ${other} (${E((lists[other] || {}).count || 0)} entries now)</option></select></label></div>
        <div class="df-hint">ATP applies these lists to every user and location as soon as ZIA activates the change, so applying asks for the typed phrase.</div>${list}`;
    }
    return `${head}${rec}<div class="op-row">${inc}<label class="df-ctl"><span class="lbl">Change</span><select id="lfAct${i}" aria-label="Add the destinations to a group, or take them out">
        <option value="add"${sec.mode === 'add' ? ' selected' : ''}>Add them to a group</option>
        <option value="remove"${sec.mode === 'remove' ? ' selected' : ''}>Take them out of a group</option></select></label></div>
      ${ips.length ? `<div class="op-row">${groupSelect(H, res, i, 'ip', sec)}<span class="df-hint">${ips.length} address${ips.length === 1 ? '' : 'es'}; single addresses are merged into CIDR blocks.</span></div>` : ''}
      ${hosts.length ? `<div class="op-row">${groupSelect(H, res, i, 'host', sec)}<span class="df-hint">${hosts.length} host name${hosts.length === 1 ? '' : 's'}.</span></div>` : ''}
      ${v6.length ? `<div class="df-hint">${v6.length} IPv6 destination${v6.length === 1 ? '' : 's'} cannot go into a group: ZIA's API has no user-defined IPv6 destination group. The preview lists them as excluded.</div>` : ''}
      ${sec.mode === 'add' ? ruleBlock(H, res, i, sec) : ''}${list}`;
  }
  function rowsTable(H, rows) {
    if (!rows.length) return '';
    const E = H.E;
    return `<h3 class="op-h">Rows this fixes</h3><div class="df-tablewrap"><table class="df-table"><caption class="sr-only">Rows from Test a list</caption>
      <thead><tr><th scope="col">Row</th><th scope="col">Destination</th><th scope="col">Expected</th><th scope="col">Result</th><th scope="col">Deciding rule</th></tr></thead>
      <tbody>${rows.slice(0, 500).map(r => `<tr id="lf-row-${E(r.row)}"><td class="num">${E(r.row)}</td><td>${E(r.target)}</td><td>${E(String(r.expected || '').toLowerCase())}</td>
        <td>${E(RES[r.result] || r.result)}</td><td>${E(r.rule || '–')}${r.area ? ` <span class="df-by">${E(r.area)}</span>` : ''}</td></tr>`).join('')}</tbody></table></div>`;
  }
  function manualHtml(H, z) {
    const E = H.E, m = z.manual;
    return `<div class="op-row"><label class="df-ctl"><span class="lbl">Area</span><select id="lfArea" aria-label="Area to fix">
        ${Object.entries(AREA).map(([k, l]) => `<option value="${E(k)}"${m.area === k ? ' selected' : ''}>${E(l)}</option>`).join('')}</select></label>
      <label class="df-ctl"><span class="lbl">The destinations should be</span><select id="lfPurpose" aria-label="Block or allow the destinations">
        <option value="block"${m.purpose === 'block' ? ' selected' : ''}>Blocked</option><option value="allow"${m.purpose === 'allow' ? ' selected' : ''}>Allowed</option></select></label></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Destinations, one per line</span><textarea id="lfDests" rows="4" aria-label="Destinations to fix, one per line">${E(m.text)}</textarea></label>
        <button type="button" class="rp-btn" id="lfUse">Use these</button></div>`;
  }

  function render(res, where, S, H) {
    const E = H.E, z = st(S);
    const fromList = !!(S.handoff && (S.handoff.fixes || []).length);
    const secs = z.sections || [];
    where.innerHTML = `${errs(H, res)}
      <p>${fromList ? 'These rows of the Path analyzer\'s Test a list did not do what was expected. For each area, pick where the destinations go and which rule uses them, then preview: it says each change in plain words and the rows it fixes.'
        : 'Fix destinations that did not do what was expected: pick Fix selected on the Path analyzer\'s Test a list view to fill this in, or paste them below.'} New rules arrive disabled; nothing is written until you apply.</p>
      ${fromList ? '' : manualHtml(H, z)}
      ${secs.map((sec, i) => sectionHtml(H, res, i, sec)).join('')}
      ${rowsTable(H, z.rows)}`;
    const again = id => { render(res, where, S, H); const el = id && document.getElementById(id); if (el) el.focus(); };
    const on = (id, ev, fn) => { const el = document.getElementById(id); if (el) el.addEventListener(ev, fn); };
    on('lfArea', 'change', e => { z.manual.area = e.target.value; });
    on('lfPurpose', 'change', e => { z.manual.purpose = e.target.value; });
    on('lfDests', 'input', e => { z.manual.text = e.target.value; });
    on('lfUse', 'click', () => {
      const vals = H.lines(z.manual.text).slice(0, 5000);
      z.sections = vals.length ? [section({ area: z.manual.area, purpose: z.manual.purpose, destinations: vals.map(v => ({ value: v, rows: [] })) })] : [];
      again('lfUse'); H.say(vals.length ? `${vals.length} destinations ready: pick where they go, then preview.` : 'Paste at least one destination.');
    });
    secs.forEach((sec, i) => {
      on(`lfInc${i}`, 'change', e => { sec.include = e.target.checked; });
      on(`lfAct${i}`, 'change', e => { sec.mode = e.target.value; if (sec.mode === 'remove') { if (sec.ip === 'new') sec.ip = ''; if (sec.host === 'new') sec.host = ''; } again(`lfAct${i}`); });
      on(`lfIp${i}`, 'change', e => { sec.ip = e.target.value; again(`lfIp${i}`); });
      on(`lfHost${i}`, 'change', e => { sec.host = e.target.value; again(`lfHost${i}`); });
      on(`lfIpName${i}`, 'input', e => { sec.ipName = e.target.value; });
      on(`lfHostName${i}`, 'input', e => { sec.hostName = e.target.value; });
      on(`lfRule${i}`, 'change', e => { sec.rule = e.target.value; again(`lfRule${i}`); });
      on(`lfRuleId${i}`, 'change', e => { sec.ruleId = e.target.value; });
      on(`lfRuleName${i}`, 'input', e => { sec.ruleName = e.target.value; });
      on(`lfAbove${i}`, 'change', e => { sec.above = e.target.value; });
      on(`lfOn${i}`, 'change', e => { sec.enabled = e.target.checked; });
      on(`lfSvc${i}`, 'change', e => { sec.services = Array.from(e.target.selectedOptions).map(o => o.value); });
    });
  }

  function spec(S, H) {
    const z = st(S);
    const res = S.objects.list_fix_targets || {};
    const fixes = [];
    (z.sections || []).forEach(sec => {
      if (!sec.include || !(res.areas || []).includes(sec.area)) return;
      const f = { area: sec.area, purpose: sec.purpose, action: sec.mode, destinations: sec.dests, decided_by: sec.decided.slice(0, 5) };
      if (sec.area === 'atp') { f.list = sec.mode === 'add' ? (sec.purpose === 'block' ? 'denylist' : 'allowlist') : (sec.purpose === 'block' ? 'allowlist' : 'denylist'); fixes.push(f); return; }
      const ref = (v, name) => v === 'new' ? { new: String(name || '').trim() } : v ? { id: v } : null;
      const hasIp = sec.dests.some(d => isIp(d.value)), hasHost = sec.dests.some(d => !isIp(d.value) && !isV6(d.value));
      f.ip_group = hasIp ? ref(sec.ip, sec.ipName) : null;
      f.fqdn_group = hasHost ? ref(sec.host, sec.hostName) : null;
      if ((hasIp && !f.ip_group) || (hasHost && !f.fqdn_group)) throw new Error(`${AREA[sec.area]}: pick the group the destinations ${sec.mode === 'add' ? 'go into' : 'come out of'}.`);
      if (sec.mode === 'add' && sec.rule === 'existing') {
        if (!sec.ruleId) throw new Error(`${AREA[sec.area]}: pick the rule to add the group to, or another choice under Then.`);
        f.rule = { id: sec.ruleId };
      } else if (sec.mode === 'add' && sec.rule === 'new') {
        f.rule = { new: { name: String(sec.ruleName || '').trim(), above: sec.above || null, enabled: !!sec.enabled } };
      } else f.rule = null;
      f.services = sec.area === 'firewall' && f.rule ? sec.services : [];
      fixes.push(f);
    });
    if (!fixes.length) throw new Error('Nothing to fix: include at least one fix that is in scope (or paste destinations and click Use these).');
    return { type: 'list_fix', fixes };
  }

  // The preview: each write in plain words, linked to the rows it fixes.
  function plan(p, where, H) {
    const ex = p.explanations || [];
    if (!ex.length) return;
    const box = document.createElement('div');
    box.className = 'bp-card info';
    box.innerHTML = `<div class="t">What this changes, in plain words</div><ol>${ex.map(e => `<li>${H.E(e.text)}${(e.rows || []).length ? ` <span class="df-by">Fixes row${e.rows.length === 1 ? '' : 's'} ${rowLinks(H, e.rows)}</span>` : ''}</li>`).join('')}</ol>`;
    const items = where.querySelector('h3.op-h:last-of-type');
    if (items) items.before(box); else where.appendChild(box);
  }

  // After an apply: Prove it tests the same rows again.
  function result(r, where, H) {
    const id = H.S.handoffId;
    if (!id || !['applied', 'partial'].includes(r.status)) return;
    const off = (r.items || []).filter(u => u.kind === 'create_rule' && u.status === 'applied' && (u.object || {}).state !== 'ENABLED').map(u => u.object.name);
    const box = document.createElement('div');
    box.className = 'bp-card';
    box.innerHTML = `<div class="t">Prove it</div><div>Test the same rows again, as Test a list did, to see which ones now do what was expected.${off.length ? ` The new rule${off.length === 1 ? '' : 's'} ${H.E(off.map(n => `'${n}'`).join(', '))} ${off.length === 1 ? 'is' : 'are'} disabled, so the rows ${off.length === 1 ? 'it covers stay' : 'they cover stay'} as they were until ${off.length === 1 ? 'it is' : 'they are'} enabled.` : ''} It only reads.</div>
      <div class="op-row"><button type="button" class="rp-btn primary" id="lfProve">Prove it: test the rows again</button></div><div id="lfProof"></div>`;
    where.appendChild(box);
    document.getElementById('lfProve').addEventListener('click', () => prove(id, H, off));
  }
  async function prove(id, H, off) {
    const E = H.E, out = document.getElementById('lfProof'), btn = document.getElementById('lfProve');
    btn.disabled = true; H.say('Testing the rows again. Nothing is written.');
    try {
      const snap = await H.runJob(`/api/bulk-test/fix/${encodeURIComponent(id)}/prove/start`, H.body({}), out, 'Testing the rows again');
      const res = snap.result || {}, pr = res.proof;
      if (!pr) throw new Error(snap.error || 'The rows could not be tested again.');
      const c = pr.counts || {};
      const chip = s => s === 'fixed' ? '<span class="df-chip st-ok">Now as expected</span>' : s === 'still' ? '<span class="df-chip st-warn">Not yet</span>' : '<span class="df-chip">Not tested</span>';
      out.innerHTML = `<p class="pl-lead" tabindex="-1" id="lfProofLead">${E(c.fixed || 0)} of ${E(pr.total || 0)} row(s) now do what was expected${c.still ? `; ${E(c.still)} not yet` : ''}${c.not_tested ? `; ${E(c.not_tested)} could not be tested` : ''}.</p>
        <div class="df-tablewrap"><table class="df-table"><caption class="sr-only">The rows tested again</caption>
        <thead><tr><th scope="col">Row</th><th scope="col">Destination</th><th scope="col">Expected</th><th scope="col">Before</th><th scope="col">Now</th><th scope="col">Deciding rule now</th><th scope="col">Verdict</th></tr></thead>
        <tbody>${(pr.rows || []).map(x => `<tr><td class="num"><a href="#lf-row-${E(x.row)}">${E(x.row)}</a></td><td>${E(x.target)}</td><td>${E(String(x.expected || '').toLowerCase())}</td><td>${E(RES[x.before] || x.before || '')}</td><td>${E(RES[x.now] || x.now)}</td>
          <td>${E(x.now_rule || '–')}${x.now_area ? ` <span class="df-by">${E(x.now_area)}</span>` : ''}</td><td>${chip(x.state)}${x.state === 'still' ? `<div class="df-by">${off.length ? E(`Still decided by ${x.now_rule || 'the same rule'}: enable ${off.map(n => `'${n}'`).join(', ')} if it covers this row, then test again.`) : E(x.recommendation || '')}</div>` : ''}</td></tr>`).join('')}</tbody></table></div>`;
      const lead = document.getElementById('lfProofLead'); if (lead) lead.focus();
      H.say(`${c.fixed || 0} of ${pr.total || 0} rows now do what was expected.`);
    } catch (e) {
      out.innerHTML = `<div class="bp-card risk" role="alert"><div class="t">The rows could not be tested again</div><div>${E(e.message)}</div></div>`;
    } finally { btn.disabled = false; }
  }

  window.OPS_PLUGINS.register({ type: 'list_fix', render, spec, plan, result });

  // ── Standalone: one IP destination group (ip_group_edit) ──
  function gst(S) { if (!S.lg) S.lg = { group: '', name: '', type: 'DSTN_IP', add: '', remove: '' }; return S.lg; }
  function renderGroup(res, where, S, H) {
    const E = H.E, z = gst(S), lim = (res.limits || {}).group_addresses || 8000;
    const groups = (res.ip_groups || []).filter(g => g.editable && ['DSTN_IP', 'DSTN_FQDN', 'DSTN_DOMAIN'].includes(g.type));
    if (!(res.areas || []).includes('firewall')) { where.innerHTML = `${errs(H, res)}<div class="bp-card warn"><div>${E((res.not_in_scope_areas || {}).firewall || 'Not in scope on the Scope page.')}</div></div>`; return; }
    where.innerHTML = `${errs(H, res)}
      <p>Add or remove entries on one IP destination group, or make a new one. A group holds IPv4 addresses, CIDR blocks and ranges (type IP) or host names (type FQDN), at most ${E(lim)} entries (assumed limit). The preview names the rules that use the group.</p>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Group</span><select id="lgGroup" aria-label="IP destination group to change">
          <option value="">Pick one…</option><option value="new"${z.group === 'new' ? ' selected' : ''}>A new group…</option>
          ${groups.map(g => `<option value="${E(g.id)}"${String(z.group) === String(g.id) ? ' selected' : ''}>${E(g.name)} (${E(g.type === 'DSTN_IP' ? 'IP' : g.type === 'DSTN_FQDN' ? 'FQDN' : 'domain')}, ${E(g.count)} of ${E(lim)})</option>`).join('')}</select></label>
        ${z.group === 'new' ? `<label class="df-ctl"><span class="lbl">New group name</span><input id="lgName" value="${E(z.name)}" maxlength="128" aria-label="Name of the new group"></label>
          <label class="df-ctl"><span class="lbl">It holds</span><select id="lgType" aria-label="What the new group holds">
            <option value="DSTN_IP"${z.type === 'DSTN_IP' ? ' selected' : ''}>IPv4 addresses, CIDR blocks and ranges</option>
            <option value="DSTN_FQDN"${z.type === 'DSTN_FQDN' ? ' selected' : ''}>Host names</option></select></label>` : ''}</div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Add, one per line</span><textarea id="lgAdd" rows="4" aria-label="Entries to add, one per line">${E(z.add)}</textarea></label>
        ${z.group !== 'new' ? `<label class="df-ctl"><span class="lbl">Remove, one per line</span><textarea id="lgRemove" rows="4" aria-label="Entries to remove, one per line">${E(z.remove)}</textarea></label>` : ''}</div>`;
    const on = (id, ev, fn) => { const el = document.getElementById(id); if (el) el.addEventListener(ev, fn); };
    on('lgGroup', 'change', e => { z.group = e.target.value; renderGroup(res, where, S, H); document.getElementById('lgGroup').focus(); });
    on('lgName', 'input', e => { z.name = e.target.value; });
    on('lgType', 'change', e => { z.type = e.target.value; });
    on('lgAdd', 'input', e => { z.add = e.target.value; });
    on('lgRemove', 'input', e => { z.remove = e.target.value; });
  }
  function specGroup(S, H) {
    const z = gst(S);
    if (!z.group) throw new Error('Pick the group to change, or a new one.');
    const add = H.lines(z.add), remove = z.group === 'new' ? [] : H.lines(z.remove);
    if (!add.length && !remove.length) throw new Error('List at least one entry to add or remove.');
    return { type: 'ip_group_edit', group: z.group === 'new' ? { new: z.name.trim(), group_type: z.type } : { id: z.group }, add, remove };
  }
  window.OPS_PLUGINS.register({ type: 'ip_group_edit', render: renderGroup, spec: specGroup, plan });

  // ── Standalone: the ATP allow and deny lists (atp_list_edit) ──
  function ast(S) { if (!S.la) S.la = { list: 'denylist', add: '', remove: '' }; return S.la; }
  function renderList(res, where, S, H) {
    const E = H.E, z = ast(S), lists = res.atp_lists || {};
    if (!(res.areas || []).includes('atp')) { where.innerHTML = `${errs(H, res)}<div class="bp-card warn"><div>${E((res.not_in_scope_areas || {}).atp || 'Not in scope on the Scope page.')}</div></div>`; return; }
    where.innerHTML = `${errs(H, res)}
      <p>Add or remove URLs on the security policy lists Advanced Threat Protection applies to every user and location: the denylist blocks, the allowlist exempts (and wins over the denylist). A change acts as soon as ZIA activates it, so applying asks for the typed phrase.</p>
      <div class="op-row"><label class="df-ctl"><span class="lbl">List</span><select id="laList" aria-label="Security policy list to change">
        <option value="denylist"${z.list === 'denylist' ? ' selected' : ''}>Denylist (${E((lists.denylist || {}).count || 0)} entries)</option>
        <option value="allowlist"${z.list === 'allowlist' ? ' selected' : ''}>Allowlist (${E((lists.allowlist || {}).count || 0)} entries)</option></select></label></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Add, one per line</span><textarea id="laAdd" rows="4" aria-label="URLs to add, one per line">${E(z.add)}</textarea></label>
        <label class="df-ctl"><span class="lbl">Remove, one per line</span><textarea id="laRemove" rows="4" aria-label="URLs to remove, one per line">${E(z.remove)}</textarea></label></div>`;
    const on = (id, ev, fn) => { const el = document.getElementById(id); if (el) el.addEventListener(ev, fn); };
    on('laList', 'change', e => { z.list = e.target.value; });
    on('laAdd', 'input', e => { z.add = e.target.value; });
    on('laRemove', 'input', e => { z.remove = e.target.value; });
  }
  function specList(S, H) {
    const z = ast(S), add = H.lines(z.add), remove = H.lines(z.remove);
    if (!add.length && !remove.length) throw new Error('List at least one URL to add or remove.');
    return { type: 'atp_list_edit', list: z.list, add, remove };
  }
  window.OPS_PLUGINS.register({ type: 'atp_list_edit', render: renderList, spec: specList, plan });
})();
