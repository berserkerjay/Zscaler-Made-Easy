// ── FP/TP Detection Ratio renderer ───────────────────────────────────────
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
  const misconfigured = (d.misconfigured || []).length > 0;
  const deliveryCls = misconfigured ? 'st-fail' : ({ cloud: 'st-ok', icap: 'st-ok', both: 'st-ok', none: 'st-fail' }[d.path] || 'st-dim');
  const deliveryLab = { cloud: 'Zscaler Incident Receiver (cloud-to-cloud)', icap: 'On-premises Incident Receiver (ICAP)', both: 'Zscaler Incident Receiver + ICAP', none: 'No incident forwarding' }[d.path] || 'Unknown';
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
  // Who / what / where.
  const share = s.fp_share_pct;
  const ratioCls = share == null ? 'st-dim' : share >= (st.fp_rate_pct || 40) ? 'st-fail' : share >= 20 ? 'st-warn' : 'st-ok';
  const ratioText = share == null ? 'No verdicts yet: analysts have not closed an incident in this window, so the ratio cannot be measured.'
    : `${s.fp} not real for every ${s.tp} real${share >= (st.fp_rate_pct || 40) ? ': most of what the analysts look at is noise. Exclude the destinations marked below first, then tune the dictionaries.' : share >= 20 ? ': worth trimming; start with the destinations marked for exclusion.' : ': the incidents are worth an analyst\'s time.'}`;
  const userRow = u => `<tr><td>${_dhE(u.name)}${u.display_name ? ` <span class="df-by">${_dhE(u.display_name)}</span>` : ''}</td><td>${_dhE(u.department || '')}</td><td class="num">${u.incidents}</td><td class="num">${u.real || 0}</td><td class="num">${u.not_real}</td><td class="num">${u.open}</td><td>${_dhE((u.destinations || []).map(([n, c]) => `${n} (${c})`).join(', '))}</td><td>${_dhE((u.rules || []).slice(0, 3).join(', '))}${(u.rules || []).length > 3 ? '…' : ''}</td></tr>`;
  const destRow = h => `<tr class="${h.exclude ? 'dh-excl' : ''}"><td>${_dhE(h.name)}${h.telemetry ? ' <span class="df-chip st-warn" title="Matches a telemetry / public-content pattern">telemetry</span>' : ''}</td><td class="num">${h.incidents}</td><td class="num">${h.users || 0}</td><td class="num">${h.real || 0}</td><td class="num">${h.not_real}</td><td class="num">${_dhPct(h.fp_rate_pct)}</td><td>${_dhE((h.actions || []).join(', '))}</td><td>${h.exclude ? '<span class="df-chip st-fail">Exclude</span>' : (h.real ? '<span class="df-chip st-ok">Real data</span>' : '')}</td><td>${_dhE((h.rules || []).slice(0, 3).join(', '))}${(h.rules || []).length > 3 ? '…' : ''}</td></tr>`
    + (h.exclude ? `<tr class="dh-why"><td colspan="9"><div class="df-hop-d"><strong>Why:</strong> ${_dhE(h.why)}</div><div class="df-hop-d"><strong>Fix:</strong> ${_dhE(h.fix)}</div></td></tr>` : '');
  const recentRow = r => `<tr><td class="dh-when">${r.at ? _dhE(new Date(r.at).toLocaleString()) : ''}</td><td>${_dhE(r.who || '(unknown)')}${r.department ? ` <span class="df-by">${_dhE(r.department)}</span>` : ''}</td><td>${_dhE(r.trigger)}${r.dictionaries ? `<div class="df-by">${_dhE(r.dictionaries)}</div>` : ''}</td><td>${_dhE(r.sent_to || '(unknown)')}${r.file ? `<div class="df-by">${_dhE(r.file)}</div>` : ''}</td><td>${_dhE(DH_CHAN[r.channel] || r.channel)}${(r.actions || []).length ? ` · ${_dhE(r.actions.join(', '))}` : ''}</td><td><span class="df-chip ${r.verdict === 'real' ? 'st-fail' : r.verdict === 'not real' ? 'st-ok' : 'st-dim'}">${_dhE(r.verdict)}</span></td></tr>`;
  container.innerHTML = `
    <div class="df-outcome ${ratioCls}"><span class="df-chip ${ratioCls}">FP/TP ${_dhE(s.fp_tp_ratio || '–')}</span><strong>False-positive to true-positive ratio${share != null ? ` · ${share}% of verdicts not real` : ''}</strong> <span class="df-by">${_dhE(ratioText)}</span></div>
    <div class="df-hint">How it is measured: every Workflow Automation incident an analyst closed counts once; a resolution of ${_dhE((st.not_real || []).join(', '))} is a false positive (FP), any other closed incident a true positive (TP); open incidents wait. Destinations that never produce a real incident and look like telemetry or public content are marked <em>Exclude</em>: excluding them is a policy-scope fix that removes noise without losing coverage.</div>
    <div class="df-stats">
      ${tile(rep.incident_count || 0, `incidents in ${rep.days} days`)}
      ${tile(s.tp || 0, 'real (TP)')}
      ${tile(s.fp || 0, 'not real (FP)', (s.fp || 0) > (s.tp || 0))}
      ${tile(s.users || 0, 'users transacting')}
      ${tile(s.excludable_destinations || 0, 'destinations to exclude', !!s.excludable_destinations)}
      ${tile(s.closed || 0, 'closed by analysts')}
      ${tile(_dhPct(s.fp_rate_pct), `not real, ${st.fp_window_days}-day window`, (s.fp_rate_pct || 0) >= (st.fp_rate_pct || 40))}
      ${tile(s.noisy_rules || 0, 'noisy rules', !!s.noisy_rules)}
      ${tile(s.dead_rules || 0, 'dead rules', !!s.dead_rules)}
      ${tile(s.promotable_rules || 0, 'ready to promote')}
      ${tile(s.noisy_dictionaries || 0, 'noisy dictionaries', !!s.noisy_dictionaries)}
    </div>
    <div class="df-outcome ${deliveryCls}"><span class="df-chip ${deliveryCls}">${misconfigured ? 'Configured but not delivering' : _dhE(deliveryLab)}</span><strong>How incidents reach Workflow Automation</strong> <span class="df-by">${d.rules_enabled || 0} enabled Web DLP rule(s): ${d.rules_cloud || 0} set to Zscaler Incident Receiver (cloud-to-cloud), ${d.rules_icap || 0} to an on-premises Incident Receiver over ICAP${(d.rules_silent || []).length ? `, ${d.rules_silent.length} forward nowhere` : ''}${(d.receivers || []).length ? ` · Incident Receiver objects: ${_dhE(d.receivers.map(x => x.name).join(', '))}` : ' · no Incident Receiver object configured'}${(d.icap_servers || []).length ? ` · ICAP server objects: ${_dhE(d.icap_servers.map(x => x.name).join(', '))}` : ''}</span></div>
    <div class="df-hint">${_dhE(d.explain || '')}${(d.rules_silent || []).length ? ` Rules that forward nowhere: ${_dhE(d.rules_silent.slice(0, 8).join(', '))}${d.rules_silent.length > 8 ? '…' : ''}.` : ''}</div>
    ${misconfigured ? `<ul class="df-weaks">${d.misconfigured.map(m => `<li class="sev-high"><span class="sev">high</span> <strong>Incident delivery configured but not working (${m.path === 'cloud' ? 'cloud-to-cloud' : 'ICAP'})</strong><div class="df-hop-d">${_dhE(m.text)}</div></li>`).join('')}</ul>` : ''}
    ${rep.read && (!rep.read.incidents || !rep.read.rules) ? `<div class="df-gap-h st-fail">Partial read</div><div class="df-hint">${!rep.read.incidents ? 'Workflow Automation incidents could not be read, so there are no verdicts to learn from — grant the API client the Workflow Automation read scope. ' : ''}${!rep.read.rules ? 'The DLP rules of the tenant could not be listed. ' : ''}See the read problems at the bottom.</div>` : ''}
    <h2 class="df-h">Findings, worst first</h2>
    ${findings ? `<ul class="df-weaks">${findings}</ul>` : '<div class="df-hop-d">Nothing to act on in this window.</div>'}
    <h2 class="df-h">Where it was going</h2>
    ${table(['Destination', 'Incidents', 'Users', 'Real', 'Not real', 'FP %', 'Actions', '', 'Rules'], (rep.destinations || []).map(destRow).join(''))}
    <div class="df-hint">The host, application or recipient domain each incident was headed to. <em>telemetry</em>: the host or path matches a known telemetry, analytics, crash-report, update or certificate pattern. <em>Exclude</em>: at least ${st.dest_min_incidents || 3} incidents, none closed as real, and either a telemetry pattern or ${st.dest_fp_pct || 80}% or more of the closed ones not real; the proposal names the rules to exclude it from.</div>
    <h2 class="df-h">Who is transacting</h2>
    ${table(['User', 'Department', 'Incidents', 'Real', 'Not real', 'Open', 'Top destinations', 'Rules'], (rep.users || []).map(userRow).join(''))}
    <h2 class="df-h">Latest transactions: who, what triggered, where it was going</h2>
    ${table(['When', 'Who', 'Trigger (rule · dictionaries)', 'Sent to', 'Channel · action', 'Verdict'], (rep.recent || []).map(recentRow).join(''))}
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
    <div class="df-cc">Sources: ${_dhE((rep.sources || {}).incidents || '')} · ${_dhE((rep.sources || {}).rules || '')}. User identities appear as Workflow Automation records them; the report stays in this server's memory and is never written to disk.</div>`;
}
window.renderDetectionHealth = renderDetectionHealth;


// ── Proposals: the approval queue ───────────────────────────────────
// Typed proposals built from this report (and the 6-hour refresh):
// a person approves, dismisses or snoozes each one. Nothing is written
// to the tenant from here; approved proposals wait for the apply step.
const DH_PSTATUS = { open: ['Open', 'warn'], approved: ['Approved, ready to apply', 'ok'], snoozed: ['Snoozed', 'dim'], dismissed: ['Dismissed', 'dim'], applied: ['Applied', 'ok'], rolled_back: ['Rolled back', 'dim'], resolved: ['Resolved', 'dim'], failed: ['Apply failed', 'fail'] };
// Credentials for applying: the assessment page that opened this tab (its
// tenant details), else the profile the report was made from.
function _dhCreds() {
  try { if (window.opener && !window.opener.closed && typeof window.opener.migrateValidateCreds === 'function') { const b = window.opener.migrateValidateCreds(); if (b) return b; } } catch (e) { /* cross-window */ }
  return { profile_id: (window.__dhReport || {}).profile_id || '' };
}
async function _dhPost(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((d.detail && (d.detail.cause || d.detail)) || `HTTP ${r.status}`);
  return d;
}
function _dhStepsHtml(pv) {
  return `<table class="dh-steps"><thead><tr><th scope="col">Rule</th><th scope="col">Channel</th><th scope="col">${_dhE(pv.field)} now</th><th scope="col">→</th><th scope="col">Check</th></tr></thead><tbody>${(pv.steps || []).map(s => `<tr><td>${_dhE(s.name)}</td><td>${_dhE(s.channel_label || s.channel)}</td><td>${_dhE(s.current == null ? '—' : s.current)}</td><td>${_dhE(s.to == null ? '—' : s.to)}</td><td class="${s.ok ? (s.noop ? 'dim' : 'ok') : 'fail'}">${_dhE(s.result ? (s.result + (s.verified ? ', read back and verified' : '')) : (s.ok ? (s.noop ? 'no change needed' : 'ready') : 'refused'))}${s.why ? ': ' + _dhE(s.why) : ''}</td></tr>`).join('')}</tbody></table>`;
}
// Preview → confirm → apply (or roll back), with the read-back shown.
async function _dhApplyFlow(tenant, p, direction, box, host) {
  const creds = _dhCreds();
  box.innerHTML = '<div class="df-hint">Reading the rules in the tenant…</div>';
  let pv;
  try { pv = await _dhPost(`/api/proposals/${encodeURIComponent(tenant)}/${encodeURIComponent(p.id)}/preview?direction=${direction}`, creds); }
  catch (e) { box.innerHTML = `<div class="df-hint">Could not preview: ${_dhE(e.message)}</div>`; return; }
  const verb = direction === 'apply' ? 'Apply' : 'Roll back';
  box.innerHTML = `<div class="dh-preview"><strong>${verb}: what would change</strong>${_dhStepsHtml(pv)}
    <div class="df-hint">${_dhE(pv.note || '')}</div>
    <div class="dh-pactions">${pv.ok && pv.changes ? `<label class="df-ctl"><input type="checkbox" class="dh-ok"> <span class="lbl">I have reviewed the change and want it applied to the tenant</span></label><button type="button" class="rp-btn primary" data-go="${direction}" disabled>${verb} now</button>` : `<span class="df-by">${pv.ok ? 'Nothing to change.' : 'Refused: fix the reason above, refresh FP/TP Detection Ratio and decide again.'}</span>`}<button type="button" class="rp-btn" data-cancel="1">Close</button></div></div>`;
  const cb = box.querySelector('.dh-ok'), go = box.querySelector('[data-go]');
  if (cb && go) cb.addEventListener('change', () => { go.disabled = !cb.checked; });
  box.querySelector('[data-cancel]').addEventListener('click', () => { box.innerHTML = ''; });
  if (go) go.addEventListener('click', async () => {
    go.disabled = true;
    box.querySelector('.df-hint').textContent = `${verb === 'Apply' ? 'Applying' : 'Rolling back'}… each rule is updated and read back.`;
    try {
      const out = await _dhPost(`/api/proposals/${encodeURIComponent(tenant)}/${encodeURIComponent(p.id)}/${direction}`, { ...creds, confirm: true, by: (host.querySelector('#dhBy') || {}).value || '' });
      box.innerHTML = `<div class="dh-preview"><strong>${out.ok ? (direction === 'apply' ? 'Applied and verified.' : 'Rolled back and verified.') : 'Some rules could not be changed.'}</strong>${_dhStepsHtml({ field: out.field, steps: out.results })}<div class="df-hint">${_dhE(out.activation || '')}</div></div>`;
      setTimeout(() => renderProposals(tenant, host), 1500);
    } catch (e) { box.innerHTML = `<div class="df-hint">Not applied: ${_dhE(e.message)}</div>`; }
  });
}
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
    if (c.kind === 'exclude_destination') return `exclude ${c.host} from ${(c.rules || []).join(', ') || 'the DLP rules'} (URL category or domain exclusion in the ZIA portal)`;
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
      </div>` : (p.status === 'approved' && p.applies_via === 'phase 3' ? `<div class="dh-pactions"><button type="button" class="rp-btn primary" data-flow="apply" data-id="${_dhE(p.id)}">Preview and apply to the tenant</button><button type="button" class="rp-btn" data-act="reopen" data-id="${_dhE(p.id)}">Reopen</button></div><div class="dh-flow" data-box="${_dhE(p.id)}"></div>`
      : (p.status === 'applied' || p.status === 'failed') && p.applies_via === 'phase 3' ? `<div class="dh-pactions"><button type="button" class="rp-btn" data-flow="rollback" data-id="${_dhE(p.id)}">Roll back</button></div><div class="dh-flow" data-box="${_dhE(p.id)}"></div>`
      : (p.status === 'approved' || p.status === 'snoozed' || p.status === 'dismissed' ? `<div class="dh-pactions"><button type="button" class="rp-btn" data-act="reopen" data-id="${_dhE(p.id)}">Reopen</button></div>` : ''));
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
    <div class="df-hint">Each proposal names one change, the evidence behind it, the expected effect and the way back. Approving never writes anything by itself. An approved proposal gets a <em>Preview and apply</em> button: the rules are re-read, you see exactly what changes, you confirm, the app updates each rule and reads it back, and a <em>Roll back</em> stays available afterwards (write mode required; ZIA keeps the change pending until an admin activates). A change that makes the tenant stricter for users (monitor → confirm or block) needs the confirm phrase. A dismissal is remembered for ${data.dismiss_days} days.</div>
    <ul class="dh-plist">${(data.items || []).map(row).join('') || '<li class="df-hop-d">Nothing to decide: the evaluation raised no proposal for this tenant.</li>'}</ul>`;
  host.querySelector('#dhClosed').addEventListener('change', e => { _dhPShowClosed = e.target.checked; renderProposals(tenant, host); });
  host.querySelectorAll('button[data-flow]').forEach(b => b.addEventListener('click', () => {
    const p = (data.items || []).find(x => x.id === b.dataset.id); if (!p) return;
    _dhApplyFlow(tenant, p, b.dataset.flow, host.querySelector(`.dh-flow[data-box="${CSS.escape(p.id)}"]`), host);
  }));
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
