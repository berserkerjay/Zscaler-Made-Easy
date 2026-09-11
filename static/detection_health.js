// ── Detection Health renderer ───────────────────────────────────────
// What the tenant's DLP rules actually do, from Workflow Automation
// incidents and the analysts' verdicts: per rule, engine, dictionary,
// channel and application. Pure DOM; data from /api/detection-health.
const _dhE = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const DH_STATUS = {
  noisy: ['Noisy', 'fail'], dead: ['Dead', 'warn'], promotable: ['Ready to promote', 'ok'], healthy: ['Healthy', 'ok'],
  disabled: ['Disabled', 'dim'], unknown_rule: ['Not in inventory', 'warn'], no_verdicts: ['No verdicts yet', 'dim'],
};
const DH_CHAN = { web: 'Web DLP', endpoint: 'Endpoint DLP', saas: 'SaaS Security API', email: 'Email DLP', other: 'Other' };
const _dhPct = v => (v == null ? '–' : `${v}%`);
const _dhSev = s => ({ medium: 'sev-medium', low: 'sev-low', info: 'sev-info' }[s] || 'sev-info');

function renderDetectionHealth(rep, container) {
  const s = rep.summary || {}, st = rep.settings || {}, d = rep.delivery || {};
  const tile = (n, l, bad) => `<div class="df-stat ${bad ? 'bad' : ''}"><div class="n">${_dhE(n)}</div><div class="l">${_dhE(l)}</div></div>`;
  const deliveryCls = { cloud: 'st-ok', icap: 'st-ok', both: 'st-ok', none: 'st-fail' }[d.path] || 'st-dim';
  const deliveryLab = { cloud: 'Cloud-to-cloud forwarding', icap: 'On-premises Incident Receiver (ICAP)', both: 'Cloud-to-cloud and ICAP', none: 'No incident forwarding' }[d.path] || 'Unknown';
  const findings = (rep.findings || []).map(f => `<li class="${_dhSev(f.severity)}"><span class="sev">${_dhE(f.severity)}</span> <strong>${_dhE(f.name)}</strong>${f.channel ? ` <span class="df-by">${_dhE(DH_CHAN[f.channel] || f.channel)}</span>` : ''}<div class="df-hop-d">${_dhE(f.why && f.why.length ? f.text.split(' Why: ')[0] : f.text)}</div>${f.why && f.why.length ? `<div class="df-hop-d"><strong>Why:</strong> ${_dhE(f.why.join(' '))}</div><div class="df-hop-d"><strong>Fix:</strong> ${_dhE(f.fix || '')}</div>` : ''}</li>`).join('');
  const ruleRow = r => {
    const [lab, cls] = DH_STATUS[r.status] || [r.status, 'dim'];
    return `<tr><td>${_dhE(r.name)}${r.tagged ? ' <span class="df-chip st-dim" title="created by DLP-Check">pack</span>' : ''}</td><td>${_dhE(DH_CHAN[r.channel] || r.channel || '')}</td><td>${_dhE((r.state || '').toLowerCase())}${r.monitor_only ? ' · monitor' : ''}</td><td class="num">${r.incidents}</td><td class="num">${r.open}</td><td class="num">${r.closed}</td><td class="num">${r.not_real}</td><td class="num">${_dhPct(r.fp_rate_pct)}</td><td><span class="df-chip st-${cls}" title="${_dhE(r.why || '')}">${_dhE(lab)}</span></td></tr>`;
  };
  const grpRow = g => `<tr><td>${_dhE(g.name)}</td><td class="num">${g.incidents}</td><td class="num">${g.closed}</td><td class="num">${g.not_real}</td><td class="num">${_dhPct(g.fp_rate_pct)}</td><td>${g.noisy ? '<span class="df-chip st-fail">Noisy</span>' : ''}</td><td>${_dhE((g.rules || []).slice(0, 4).join(', '))}${(g.rules || []).length > 4 ? '…' : ''}</td></tr>`
    + (g.noisy && (g.why || []).length ? `<tr class="dh-why"><td colspan="7"><div class="df-hop-d"><strong>Why it is noisy:</strong> ${_dhE(g.why.join(' '))}</div><div class="df-hop-d"><strong>Fix:</strong> ${_dhE(g.fix || '')}</div>${_dhEvidence(g.evidence)}</td></tr>` : '');
  const _dhEvidence = ev => {
    if (!ev || !ev.not_real) return '';
    const bits = [];
    if (ev.alone != null) bits.push(`fired alone in ${ev.alone} of ${ev.not_real} not-real incidents`);
    if (ev.co_fired && ev.co_fired.length) bits.push(`co-fired with ${ev.co_fired.map(([n, c]) => `${n} (${c})`).join(', ')}`);
    if (ev.median_matches_not_real != null) bits.push(`typical matches per not-real incident: ${ev.median_matches_not_real}${ev.median_matches_real != null ? `, per real incident: ${ev.median_matches_real}` : ''}`);
    if (ev.applications && ev.applications.length) bits.push(`top applications: ${ev.applications.map(([n, c]) => `${n} (${c})`).join(', ')}`);
    if (ev.departments && ev.departments.length) bits.push(`top departments: ${ev.departments.map(([n, c]) => `${n} (${c})`).join(', ')}`);
    const d = ev.definition;
    if (d) bits.push(`dictionary: ${d.custom ? 'custom' : 'predefined'}${d.type ? ', ' + d.type.toLowerCase().replace(/_/g, ' ') : ''}${d.predefined_confidence ? ', confidence ' + String(d.predefined_confidence).replace(/CONFIDENCE_LEVEL_/i, '').toLowerCase() : ''}${d.confidence_threshold != null ? ', threshold ' + d.confidence_threshold : ''}${d.custom ? `, ${d.phrases} phrase(s), ${d.patterns} pattern(s)${d.proximity_enabled ? ', proximity on' : ''}` : ''}`);
    return `<div class="df-hop-d dh-ev">Evidence: ${_dhE(bits.join(' · '))}.</div>`;
  };
  const table = (head, rows) => `<div class="df-tablewrap"><table class="df-table"><thead><tr>${head.map(h => `<th>${_dhE(h)}</th>`).join('')}</tr></thead><tbody>${rows || '<tr><td colspan="9" class="df-hop-d">Nothing in this window.</td></tr>'}</tbody></table></div>`;
  container.innerHTML = `
    <div class="df-stats">
      ${tile(rep.incident_count || 0, `incidents in ${rep.days} days`)}
      ${tile(s.closed || 0, 'closed by analysts')}
      ${tile(_dhPct(s.fp_rate_pct), `not real, ${st.fp_window_days}-day window`, (s.fp_rate_pct || 0) >= (st.fp_rate_pct || 40))}
      ${tile(s.noisy_rules || 0, 'noisy rules', !!s.noisy_rules)}
      ${tile(s.dead_rules || 0, 'dead rules', !!s.dead_rules)}
      ${tile(s.promotable_rules || 0, 'ready to promote')}
      ${tile(s.noisy_dictionaries || 0, 'noisy dictionaries', !!s.noisy_dictionaries)}
    </div>
    <div class="df-outcome ${deliveryCls}"><span class="df-chip ${deliveryCls}">${_dhE(deliveryLab)}</span><strong>How incidents reach Workflow Automation</strong> <span class="df-by">${d.rules_enabled || 0} enabled Web DLP rule(s): ${d.rules_cloud || 0} forward cloud-to-cloud, ${d.rules_icap || 0} over ICAP${(d.rules_silent || []).length ? `, ${d.rules_silent.length} forward nowhere` : ''}${(d.receivers || []).length ? ` · receivers: ${_dhE(d.receivers.map(x => x.name).join(', '))}` : ''}${(d.icap_servers || []).length ? ` · ICAP servers: ${_dhE(d.icap_servers.map(x => x.name).join(', '))}` : ''}</span></div>
    <div class="df-hint">${_dhE(d.explain || '')}${(d.rules_silent || []).length ? ` Rules that forward nowhere: ${_dhE(d.rules_silent.slice(0, 8).join(', '))}${d.rules_silent.length > 8 ? '…' : ''}.` : ''}</div>
    ${rep.read && (!rep.read.incidents || !rep.read.rules) ? `<div class="df-gap-h st-fail">Partial read</div><div class="df-hint">${!rep.read.incidents ? 'Workflow Automation incidents could not be read, so there are no verdicts to learn from — grant the API client the Workflow Automation read scope. ' : ''}${!rep.read.rules ? 'The DLP rules of the tenant could not be listed. ' : ''}See the read problems at the bottom.</div>` : ''}
    <h2 class="df-h">Findings, worst first</h2>
    ${findings ? `<ul class="df-weaks">${findings}</ul>` : '<div class="df-hop-d">Nothing to act on in this window.</div>'}
    <h2 class="df-h">Rules</h2>
    ${table(['Rule', 'Channel', 'State', 'Incidents', 'Open', 'Closed', 'Not real', `FP % (${st.fp_window_days}d)`, 'Status'], (rep.rules || []).map(ruleRow).join(''))}
    <div class="df-hint">Noisy: at least ${st.fp_min_incidents} closed incidents in ${st.fp_window_days} days and ${st.fp_rate_pct}% or more not real. Dead: enabled with no incident in ${st.dead_days} days. Ready to promote: monitor-only, at least ${st.promote_min_incidents} closed incidents in ${st.promote_window_days} days and ${st.promote_fp_pct}% or fewer not real. "Not real" means the analyst closed it as: ${_dhE((st.not_real || []).join(', '))}.</div>
    <h2 class="df-h">Dictionaries</h2>
    ${table(['Dictionary', 'Incidents', 'Closed', 'Not real', 'FP %', '', 'Rules'], (rep.dictionaries || []).map(grpRow).join(''))}
    <h2 class="df-h">Engines</h2>
    ${table(['Engine', 'Incidents', 'Closed', 'Not real', 'FP %', '', 'Rules'], (rep.engines || []).map(grpRow).join(''))}
    <h2 class="df-h">By channel</h2>
    ${table(['Channel', 'Incidents', 'Closed', 'Not real', 'FP %', '', 'Rules'], (rep.channels || []).map(c => grpRow({ ...c, name: DH_CHAN[c.name] || c.name })).join(''))}
    <h2 class="df-h">By application</h2>
    ${table(['Application', 'Incidents', 'Closed', 'Not real', 'FP %', '', 'Rules'], (rep.applications || []).map(grpRow).join(''))}
    <h2 class="df-h">By department</h2>
    ${table(['Department', 'Incidents', 'Closed', 'Not real', 'FP %', '', 'Rules'], (rep.departments || []).map(grpRow).join(''))}
    ${(rep.errors || []).length ? `<h2 class="df-h">Read problems</h2><div class="df-raw">${rep.errors.map(_dhE).join('<br>')}</div>` : ''}
    <div class="df-cc">Sources: ${_dhE((rep.sources || {}).incidents || '')} · ${_dhE((rep.sources || {}).rules || '')}. No user identities are kept in this report.</div>`;
}
window.renderDetectionHealth = renderDetectionHealth;


// ── Proposals: the approval queue ───────────────────────────────────
// Typed proposals built from this report (and the 6-hour refresh):
// a person approves, dismisses or snoozes each one. Nothing is written
// to the tenant from here; approved proposals wait for the apply step.
const DH_PSTATUS = { open: ['Open', 'warn'], approved: ['Approved, waiting to apply', 'ok'], snoozed: ['Snoozed', 'dim'], dismissed: ['Dismissed', 'dim'], applied: ['Applied', 'ok'], resolved: ['Resolved', 'dim'], failed: ['Apply failed', 'fail'] };
let _dhPTenant = null, _dhPShowClosed = false;
async function renderProposals(tenant, host) {
  if (!host) return;
  _dhPTenant = tenant;
  host.hidden = false;
  host.innerHTML = '<div class="df-hint">Loading the proposals…</div>';
  let data;
  try {
    const r = await fetch(`/api/proposals?tenant=${encodeURIComponent(tenant)}${_dhPShowClosed ? '&include_closed=true' : ''}`, { cache: 'no-store' });
    data = await r.json();
    if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
  } catch (e) { host.innerHTML = `<div class="df-hint">Proposals could not be loaded: ${_dhE(e.message)}</div>`; return; }
  const s = data.summary || {};
  const ev = (p) => {
    const e = p.evidence || {}, bits = [];
    if (e.fp_rate_pct != null) bits.push(`${e.fp_rate_pct}% not real over ${e.closed || '?'} closed in ${e.window_days || '?'} days`);
    if (e.incidents != null) bits.push(`${e.incidents} incidents`);
    if (e.last_incident_at) bits.push(`last incident ${new Date(e.last_incident_at).toLocaleDateString()}`); else if (p.kind === 'retire_rule') bits.push('no incident in the window');
    if (e.alone != null) bits.push(`fired alone in ${e.alone} of ${e.not_real} not-real incidents`);
    if (e.applications && e.applications.length) bits.push(`top applications: ${e.applications.map(([n, c]) => `${n} (${c})`).join(', ')}`);
    if (e.rules_silent && e.rules_silent.length) bits.push(`rules: ${e.rules_silent.slice(0, 6).join(', ')}`);
    if (e.engines && e.engines.length) bits.push(`engines: ${e.engines.join(', ')}`);
    if (e.why) bits.push(Array.isArray(e.why) ? e.why.join(' ') : e.why);
    return bits.join(' · ');
  };
  const change = (p) => {
    const c = p.change || {};
    if (c.apply === 'rule' && c.field) return `${c.field}: ${c.from != null ? c.from + ' → ' : ''}${c.to}${c.rules ? ' on ' + c.rules.length + ' rule(s)' : ''}`;
    if (c.kind === 'exclude_application') return `exclude ${c.application} from ${(c.rules || []).join(', ') || 'the rule'}`;
    if (c.kind === 'raise_match_count') return `raise the match count for ${c.dictionary}`;
    if (c.kind === 'review_engine') return `review engines ${(c.engines || []).join(', ')}`;
    return JSON.stringify(c);
  };
  const row = (p) => {
    const [lab, cls] = DH_PSTATUS[p.status] || [p.status, 'dim'];
    const dbl = p.gate === 'approve_double';
    const actions = p.status === 'open' ? `
      <div class="dh-pactions">
        ${dbl ? `<input type="text" class="dh-confirm" placeholder="type ${_dhE(data.confirm_phrase)}" aria-label="Confirm phrase for ${_dhE(p.title)}" data-for="${_dhE(p.id)}">` : ''}
        <button type="button" class="rp-btn primary" data-act="approve" data-id="${_dhE(p.id)}">Approve${dbl ? ' (stricter for users)' : ''}</button>
        <button type="button" class="rp-btn" data-act="snooze" data-id="${_dhE(p.id)}" title="Quiet for 14 days">Snooze</button>
        <button type="button" class="rp-btn" data-act="dismiss" data-id="${_dhE(p.id)}" title="Not raised again for ${data.dismiss_days} days">Dismiss</button>
      </div>` : (p.status === 'approved' || p.status === 'snoozed' || p.status === 'dismissed' ? `<div class="dh-pactions"><button type="button" class="rp-btn" data-act="reopen" data-id="${_dhE(p.id)}">Reopen</button></div>` : '');
    return `<li class="dh-prop st-${cls}">
      <div class="dh-phead"><span class="df-chip st-${cls}">${_dhE(lab)}</span><span class="df-chip st-dim">${_dhE(p.label)}</span><strong>${_dhE(p.title)}</strong>${p.times_seen > 1 ? ` <span class="df-by">seen ${p.times_seen}×</span>` : ''}</div>
      <div class="df-hop-d"><strong>Change:</strong> ${_dhE(change(p))} <span class="df-by">(${p.applies_via === 'phase 3' ? 'applied from here once approved' : 'made in the ZIA portal; the proposal tracks it'})</span></div>
      <div class="df-hop-d"><strong>Evidence:</strong> ${_dhE(ev(p))}</div>
      <div class="df-hop-d"><strong>Expected:</strong> ${_dhE(p.expected_effect)} <strong>Rollback:</strong> ${_dhE(p.rollback && (p.rollback.note || (p.rollback.field + ' back to ' + p.rollback.to)))}</div>
      ${p.note ? `<div class="df-hop-d"><strong>Note:</strong> ${_dhE(p.note)}${p.decided_by ? ` — ${_dhE(p.decided_by)}` : ''}</div>` : ''}
      ${actions}
    </li>`;
  };
  host.innerHTML = `
    <div class="dh-ptop">
      <h2 class="df-h" style="margin:0;">Proposals <span class="df-by">${s.open || 0} open · ${s.approved || 0} approved · ${s.snoozed || 0} snoozed · ${s.dismissed || 0} dismissed</span></h2>
      <div class="dh-pactions">
        <label class="df-ctl"><span class="lbl">Decided by</span><input type="text" id="dhBy" placeholder="your name" aria-label="Your name for the audit log"></label>
        <label class="df-ctl"><input type="checkbox" id="dhClosed" ${_dhPShowClosed ? 'checked' : ''}> <span class="lbl">show closed</span></label>
        <a class="rp-btn" href="/api/proposals/export?tenant=${encodeURIComponent(tenant)}">Markdown</a>
      </div>
    </div>
    <div class="df-hint">Each proposal names one change, the evidence behind it, the expected effect and the way back. Approving never writes anything by itself: approved proposals are applied from the deploy path with a read-back, and a change that makes the tenant stricter for users (monitor → confirm or block) needs the confirm phrase. A dismissal is remembered for ${data.dismiss_days} days.</div>
    <ul class="dh-plist">${(data.items || []).map(row).join('') || '<li class="df-hop-d">Nothing to decide: the evaluation raised no proposal for this tenant.</li>'}</ul>`;
  host.querySelector('#dhClosed').addEventListener('change', e => { _dhPShowClosed = e.target.checked; renderProposals(tenant, host); });
  host.querySelectorAll('button[data-act]').forEach(b => b.addEventListener('click', async () => {
    const id = b.dataset.id, act = b.dataset.act;
    const conf = host.querySelector(`.dh-confirm[data-for="${CSS.escape(id)}"]`);
    let note = '';
    if (act === 'dismiss') { note = window.prompt('Why dismiss it? (kept with the proposal and in the audit log)') || ''; }
    b.disabled = true;
    try {
      const r = await fetch(`/api/proposals/${encodeURIComponent(tenant)}/${encodeURIComponent(id)}/decide`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision: act, by: (host.querySelector('#dhBy') || {}).value || '', note, days: 14, confirm: conf ? conf.value : '' }) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`);
      renderProposals(tenant, host);
    } catch (e) { alert(`Could not record the decision: ${e.message}`); b.disabled = false; }
  }));
}
window.renderProposals = renderProposals;
