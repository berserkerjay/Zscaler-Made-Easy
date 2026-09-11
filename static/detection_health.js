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
  const findings = (rep.findings || []).map(f => `<li class="${_dhSev(f.severity)}"><span class="sev">${_dhE(f.severity)}</span> <strong>${_dhE(f.name)}</strong>${f.channel ? ` <span class="df-by">${_dhE(DH_CHAN[f.channel] || f.channel)}</span>` : ''}<div class="df-hop-d">${_dhE(f.text)}</div></li>`).join('');
  const ruleRow = r => {
    const [lab, cls] = DH_STATUS[r.status] || [r.status, 'dim'];
    return `<tr><td>${_dhE(r.name)}${r.tagged ? ' <span class="df-chip st-dim" title="created by DLP-Check">pack</span>' : ''}</td><td>${_dhE(DH_CHAN[r.channel] || r.channel || '')}</td><td>${_dhE((r.state || '').toLowerCase())}${r.monitor_only ? ' · monitor' : ''}</td><td class="num">${r.incidents}</td><td class="num">${r.open}</td><td class="num">${r.closed}</td><td class="num">${r.not_real}</td><td class="num">${_dhPct(r.fp_rate_pct)}</td><td><span class="df-chip st-${cls}" title="${_dhE(r.why || '')}">${_dhE(lab)}</span></td></tr>`;
  };
  const grpRow = g => `<tr><td>${_dhE(g.name)}</td><td class="num">${g.incidents}</td><td class="num">${g.closed}</td><td class="num">${g.not_real}</td><td class="num">${_dhPct(g.fp_rate_pct)}</td><td>${g.noisy ? '<span class="df-chip st-fail">Noisy</span>' : ''}</td><td>${_dhE((g.rules || []).slice(0, 4).join(', '))}${(g.rules || []).length > 4 ? '…' : ''}</td></tr>`;
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
