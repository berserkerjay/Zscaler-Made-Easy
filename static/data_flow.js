// ── Data flow map renderer ──────────────────────────────────────────
// Draws one traced path as a row of hops: the data security controls in
// the order ZIA processes a web request (device → Client Connector →
// forwarding → PAC → Cloud App Control → URL Filtering → SSL → File Type
// Control → Web DLP → logs & incidents); the controls that are not
// data-leak controls (browser/FTP, threat protection, bandwidth,
// firewall) are not drawn here, only in the reference diagram. Plus the
// parallel channels
// beneath, the weak points ranked, and every policy pack's coverage on
// that path. Pure DOM; data comes from /api/report/data-flow. Also used
// by the assessment page's mirror.
const _dfE = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const DF_STATUS = {
  pass: ['Forwarded', 'ok'], enforce: ['Enforcing', 'ok'], blocked: ['Blocked', 'block'], monitor: ['Monitor only', 'warn'],
  warn: ['Weak', 'warn'], blind: ['Encrypted / blind', 'fail'], bypass: ['Bypassed', 'fail'], none: ['No control', 'warn'],
  unknown: ['Unable to verify', 'dim'], skipped: ['Not reached', 'dim'], off: ['Not active', 'fail'],
  assumed: ['Assumed tunnel', 'dim'], na: ['Not evaluated', 'dim'], step: ['Step', 'ok'],
  out_of_scope: ['Not in scope', 'dim'], not_reached: ['Not reached', 'dim'], conditional: ['Conditional', 'dim'],
  inventory: ['Inventory only', 'dim'], metadata_only: ['No content scan', 'dim'],
  zpa_allowed: ['Carried by ZPA', 'ok'], zpa_denied: ['Blocked by ZPA', 'block'], zpa_conditional: ['Depends on the user', 'dim'],
};
const DF_OUTCOME = {
  bypassed: ['Never reaches Zscaler', 'fail'], blocked: ['Blocked before content', 'block'], blind: ['Reaches ZIA encrypted: DLP blind', 'fail'],
  enforce: ['Configured to enforce', 'ok'], monitor: ['Configured to monitor', 'warn'], none: ['No matching DLP rule', 'warn'],
  conditional: ['Applicability conditional', 'dim'], metadata_only: ['No content-inspecting engine established', 'dim'],
  unknown: ['Unable to verify the path or rules', 'dim'],
  out_of_scope: ['Not in scope: not assessed', 'dim'],
  zpa_allowed: ['Carried by ZPA and allowed: ZIA does not apply', 'ok'], zpa_denied: ['Blocked by ZPA: ZIA does not apply', 'block'],
  zpa_conditional: ['ZPA: depends on the user or device', 'dim'],
};
const DF_HOP_ORDER = ['device', 'zcc', 'forwarding', 'pac', 'cac', 'url', 'ssl', 'ftc', 'dlp', 'incident'];

// How ZIA processes a policy, from the user's device to incident
// management. Order per Zscaler's "Understanding Policy Enforcement"
// (help.zscaler.com/zia/understanding-policy-enforcement): for a web
// request, Browser Control → FTP Control → URL & Cloud App Control → SSL
// inspection → Malware Protection → Advanced Threat Protection → upload
// File Type Control → upload Bandwidth Control → DLP → Firewall & DNS
// Control; the response walks the list in reverse; the first violation
// ends the transaction. Then Nanolog, NSS, the Incident Receiver and
// Workflow Automation.
const DF_ENFORCEMENT = [
  { key: 'device', label: 'Device', sub: 'user action', text: 'A user uploads, posts, pastes, mails or copies a file. On a managed device Client Connector owns the traffic; Endpoint DLP (if installed) inspects USB, print, network share and desktop-app actions locally and reports through the same log and incident path below.' },
  { key: 'zcc', label: 'Client Connector app profile', sub: 'bypass lists', text: 'The app profile for the platform decides whether this destination is forwarded at all: hostname, IP and application bypasses send it direct, so nothing in ZIA ever sees it. Strict enforcement stops the user switching the client off.' },
  { key: 'forwarding', label: 'Forwarding profile', sub: 'per network', text: 'For the detected network (trusted, off-trusted, VPN) the forwarding profile chooses Z-Tunnel 2.0, tunnel with local proxy, enforce-PAC, or none. Only tunnelled or proxied traffic reaches ZIA; "none" relies on a site GRE/IPsec tunnel.' },
  { key: 'pac', label: 'PAC file', sub: 'DIRECT vs proxy', text: 'In PAC-based modes the PAC returns DIRECT or a ZIA proxy per URL. DIRECT never reaches Zscaler; Z-Tunnel 2.0 makes this step moot for most traffic.' },
  { key: 'browser', label: 'Browser & FTP Control', sub: 'enforced first', text: 'The request reaches the Zscaler service edge. Browser Control is enforced first (block browsers or plugins that miss the corporate standard), then FTP Control.' },
  { key: 'cac', label: 'Cloud App Control', sub: 'with URL Filtering, before SSL', text: 'URL & Cloud App Control come next. Cloud App Control rules per application category allow, caution, block or isolate specific actions (upload, share, post, view) and can gate on user risk score. When a Cloud App Control rule matches the application, URL Filtering is not applied to that transaction. Until the traffic is decrypted these controls see only the domain.' },
  { key: 'url', label: 'URL Filtering', sub: 'first match in order', text: 'If no Cloud App Control rule matched, URL Filtering rules are evaluated in order and the first match applies: ALLOW, CAUTION, BLOCK or ISOLATE per category, user, location, time and risk score.' },
  { key: 'ssl', label: 'SSL inspection', sub: 'decrypt or not', text: 'SSL inspection rules, in order, decide DECRYPT, DO NOT DECRYPT or BLOCK. Without decryption ZIA only sees the domain (SNI or certificate), so file type, malware and DLP controls that need the content or the request path cannot apply.' },
  { key: 'threat', label: 'Threat protection', sub: 'malware · ATP · sandbox', text: 'Malware Protection, then Advanced Threat Protection, are enforced on the request; on the response Sandbox and the same engines run again. A violation stops the transaction before any data control runs.' },
  { key: 'ftc', label: 'File Type Control', sub: 'upload, by category', text: 'Upload File Type Control allows, cautions or blocks whole file categories for the matched application or URL category, before content is inspected (download File Type Control runs on the response).' },
  { key: 'bandwidth', label: 'Bandwidth Control', sub: 'upload classes', text: 'Upload Bandwidth Control classes can throttle the transaction; they never stop it.' },
  { key: 'dlp', label: 'Web DLP', sub: 'engines & dictionaries', text: 'DLP rules are evaluated in order and the first match applies (or, with "Evaluate all DLP rules" on, every rule is evaluated and the most restrictive action wins). Each rule scans the content (OCR when enabled) with its engines: dictionaries, match counts and proximity. Actions: ALLOW (monitor), CONFIRM (caution page), BLOCK, or ICAP to an external receiver; sub-rules refine the parent.' },
  { key: 'firewall', label: 'Firewall & DNS Control', sub: 'last on the request', text: 'Firewall and DNS Control are the last policies enforced on the request, and the first on the response, which then walks the same list back in reverse (DLP, Bandwidth, download File Type Control, ATP, Malware, SSL, URL & Cloud App Control, FTP, Browser Control).' },
  { key: 'action', label: 'Enforcement', sub: 'what the user sees', text: 'BLOCK or CONFIRM shows the end-user notification page (or the caution dialog) and the transaction stops or waits; ALLOW lets it through to the destination and records the match.' },
  { key: 'log', label: 'Logs', sub: 'Nanolog · NSS', text: 'Every transaction writes a web log; a DLP match adds the DLP log line (rule, engine, dictionaries and counts, user, URL, file name/hash, severity). Logs land in Nanolog and Web Insights and stream through NSS or Cloud NSS to your SIEM.' },
  { key: 'incident', label: 'Incident Receiver', sub: 'cloud-to-cloud or ICAP', text: 'A rule can configure evidence forwarding to a Zscaler Incident Receiver or an ICAP server. A server reference alone does not establish Workflow Automation delivery: the receiver deployment, customer storage, events and integration must be verified.' },
  { key: 'workflow', label: 'Workflow Automation', sub: 'triage · notify · resolve', text: 'Workflow Automation can ingest incidents through a supported configured integration. This configuration report does not observe successful delivery; verify integration readiness and correlate an actual incident.' },
];

// The Path analyzer's framework: the same flow with what it checks before
// ZIA. ZPA comes first (Client Connector sends a destination a ZPA
// application segment matches to ZPA, never to ZIA), a workload's traffic
// is forwarded by its Cloud or Branch Connector instead of Client
// Connector, and the PAC file is evaluated, never run.
const DF_PATH_ENFORCEMENT = (() => {
  const zpa = { key: 'zpa', label: 'ZPA', sub: 'checked first', text: 'Client Connector checks ZPA before anything else: the application segment that matches the destination and port, the segment\'s bypass setting, the client forwarding policy and the access policy. A destination ZPA carries goes to the application through ZPA and never reaches ZIA. Traffic from a workload is forwarded by its Cloud or Branch Connector instead, whose forwarding rules send it to ZIA, to ZPA, direct, or drop it.' };
  const out = DF_ENFORCEMENT.map(s => (s.key !== 'pac' ? s : Object.assign({}, s, {
    text: s.text + ' The Path analyzer evaluates the PAC file for the destination (parsed and interpreted, never run) and says what it answers.' })));
  out.splice(1, 0, zpa);
  return out;
})();

// The reference flow as a diagram in the same style as a traced path,
// with an explanation per stage; clicking a stage scrolls to its text.
// `stages` is DF_ENFORCEMENT unless a page gives its own (DF_PATH_ENFORCEMENT).
function renderPolicyEnforcementFlow(container, stages) {
  const list = stages || DF_ENFORCEMENT;
  const t = { platform: 'Any device', network: 'any network',
    hops: list.filter(s => s.key !== 'device').map(s => ({ key: s.key, label: s.label, status: 'step', detail: s.sub })) };
  const steps = list.map((s, i) => `<li class="df-step" data-hop="${_dfE(s.key)}"><strong>${i + 1}. ${_dfE(s.label)}</strong> <span class="df-by">${_dfE(s.sub)}</span><div class="df-hop-d">${_dfE(s.text)}</div></li>`).join('');
  container.innerHTML = `<div class="df-flow-wrap">${_dfSvg(t)}</div>
    <div class="df-hint">Reference model for a ZIA web request; it is not a universal execution order for every channel or transaction. Click a stage for what it does. Endpoint DLP, SaaS Security API and Email DLP have separate capture and rule flows. Each channel requires its own supported evidence delivery integration.</div>
    <ol class="df-steps">${steps}</ol>
    <div class="df-hint">Source: Zscaler, <em>Understanding Policy Enforcement</em> (help.zscaler.com/zia/understanding-policy-enforcement) for the request and response order; Zscaler DLP Incident Receiver and Workflow Automation documentation for what follows a match.</div>`;
  container.querySelectorAll('.df-node').forEach(n => {
    const go = () => { const el = container.querySelector(`.df-step[data-hop="${n.dataset.hop}"]`); if (el) { el.scrollIntoView({ block: 'center', behavior: 'smooth' }); el.classList.add('sel'); setTimeout(() => el.classList.remove('sel'), 1600); } };
    n.addEventListener('click', go);
    n.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
  });
}

function _dfSvg(t) {
  const hops = [{ key: 'device', label: 'Device', status: 'pass', detail: `${t.platform}, ${t.network}` }].concat(t.hops.filter(h => h.key !== 'zia'));
  const ruleLines = h => String((h.decided_by && h.decided_by.name) || h.why || (h.key === 'ssl' && h.status === 'blind' ? 'No matching SSL rule' : 'Rule unavailable')).match(/.{1,26}/gu) || [];
  const ruleAction = h => (h.decided_by && h.decided_by.action) || (h.key === 'ssl' && h.decided_by ? ({pass: 'DECRYPT', blind: 'DO NOT DECRYPT', blocked: 'BLOCK'}[h.status]) : '') || '';
  const named = h => h.key === 'ssl' || !!(h.decided_by && h.decided_by.name);
  const W = 168, H = Math.max(62, ...hops.filter(named).map(h => 66 + ruleLines(h).length * 12)), GAP = 34, PAD = 14, TOP = 30;
  const width = PAD * 2 + hops.length * W + (hops.length - 1) * GAP;
  const height = TOP + H + PAD + 10;
  let out = '';
  hops.forEach((h, i) => {
    const x = PAD + i * (W + GAP), y = TOP;
    const [lab, cls] = DF_STATUS[h.status] || [h.status, 'dim'];
    // An unreadable hop shows its reason on the box, not just "could not read".
    const name = h.decided_by && h.decided_by.name ? h.decided_by.name : (h.why || h.mode || h.profile || '');
    if (i > 0) {
      const px = x - GAP, cy = y + H / 2;
      const prev = hops[i - 1];
      const dead = prev.status === 'bypass' || prev.status === 'blocked' || ['skipped', 'not_reached'].includes(h.status);
      // S-curve connector (like the deployment pack diagram) so the
      // animated dashed line reads as a flowing squiggle between hops.
      out += `<path class="df-edge ${dead ? 'dead' : ''}" d="M${px},${cy} C${px + GAP * 0.6},${cy - 16} ${x - GAP * 0.6},${cy + 16} ${x},${cy}"/>`;
    }
    out += `<g class="df-node st-${cls}" data-hop="${_dfE(h.key)}" transform="translate(${x},${y})" tabindex="0" role="button" aria-label="${_dfE(h.label)}: ${_dfE(lab)}${named(h) ? ` · ${_dfE(name || 'No matching SSL rule')} · ${_dfE(ruleAction(h))}` : ''}">
      <title>${_dfE(h.label)}: ${_dfE(name || h.detail || '')}${named(h) ? ` · ${_dfE(ruleAction(h))}` : ''}</title>
      <rect class="box" width="${W}" height="${H}" rx="12"/><rect class="bar" x="6" y="6" width="4" height="${H - 12}" rx="2"/>
      <text class="kind" x="18" y="17">${_dfE(h.label.toUpperCase())}</text>
      <text class="st" x="18" y="35">${_dfE(lab)}</text>
      ${named(h) ? ruleLines(h).map((line, n) => `<text class="sub" x="18" y="${51 + n * 12}">${_dfE(line)}</text>`).join('') + `<text class="sub" x="18" y="${51 + ruleLines(h).length * 12}">${_dfE(ruleAction(h))}</text>` : `<text class="sub" x="18" y="51">${_dfE((name || h.detail || '').slice(0, 26))}${(name || h.detail || '').length > 26 ? '…' : ''}</text>`}
      ${h.weak_point ? `<circle class="dot sev-${_dfE(h.weak_point.severity)}" cx="${W - 12}" cy="12" r="5"><title>${_dfE(h.weak_point.title)}</title></circle>` : ''}
    </g>`;
  });
  return `<svg class="df-svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="group" aria-label="Path from the device to the destination">${out}</svg>`;
}

function _dfHopDetail(h) {
  const [lab, cls] = DF_STATUS[h.status] || [h.status, 'dim'];
  return `<div class="df-hop st-${cls}" data-hop="${_dfE(h.key)}">
    <div class="df-hop-h"><span class="df-chip st-${cls}">${_dfE(lab)}</span><strong>${_dfE(h.label)}</strong>${h.decided_by && h.decided_by.name ? `<span class="df-by">decided by <code>${_dfE(h.decided_by.name)}</code>${h.decided_by.order != null ? ` (order ${_dfE(h.decided_by.order)})` : ''}</span>` : ''}</div>
    ${h.why ? `<div class="df-hop-d"><strong>Why:</strong> ${_dfE(h.why)}.</div>` : ''}
    <div class="df-hop-d">${_dfE(h.detail)}</div>
    ${h.rules && h.rules.length ? `<ul class="df-rules">${h.rules.map(r => `<li><code>${_dfE(r.name)}</code> ${_dfE(r.action)}${r.enforcing ? ' · enforcing' : ' · monitor'}${r.engines && r.engines.length ? ` · engines: ${_dfE(r.engines.slice(0, 4).join(', '))}${r.engines.length > 4 ? '…' : ''}` : ''}${r.incident_receiver || r.icap_server ? ` · → ${_dfE(r.icap_server || 'Zscaler Incident Receiver')}` : ''}${r.notification_template ? ` · notifies via ${_dfE(r.notification_template)}` : ''}</li>`).join('')}</ul>` : ''}
    ${h.forwarders ? `<div class="df-hop-d">To the Incident Receiver: ${h.forwarders.length ? _dfE(h.forwarders.join(', ')) : 'none'} · auditor notifications: ${h.notifiers && h.notifiers.length ? _dfE(h.notifiers.join(', ')) : 'none'}</div>` : ''}
    ${h.candidate_rules && h.candidate_rules.length ? `<div class="df-hop-d">Candidate rules: ${_dfE(h.candidate_rules.map(r => `${r.name} (${r.action || (r.actions || []).join(', ')})`).join('; '))}. Applicability is unverified.</div>` : ''}
    ${h.actions && h.actions.length ? `<div class="df-hop-d">Actions: ${_dfE(h.actions.join(', '))}</div>` : ''}
    ${h.raw ? `<div class="df-raw">raw: ${_dfE(JSON.stringify(h.raw))}</div>` : ''}
    ${h.weak_point ? `<div class="df-weak sev-${_dfE(h.weak_point.severity)}"><span class="sev">${_dfE(h.weak_point.severity)}</span> <strong>${_dfE(h.weak_point.title)}</strong> — ${_dfE(h.weak_point.fix)}</div>` : ''}
  </div>`;
}

function connectorInventoryHtml(c) {
  if (!c) return '';
  const apps = (c.profiles || []).map(p => { const a = p.app_profile || {}, f = p.forwarding_profile; return `<li>${_dfE(a.name)} (ID ${_dfE(a.id)}, ${_dfE(a.platform)}, ${a.active === false ? 'inactive' : 'active'}) → ${f ? `${_dfE(f.name)} (ID ${_dfE(f.id)})` : 'Forwarding link unverified'}</li>`; }).join('');
  const forwarding = (c.forwarding_profiles || []).map(f => `<li>${_dfE(f.name)} (ID ${_dfE(f.id)})</li>`).join('');
  const pac = (c.pac_files || []).map(f => `<li>${_dfE(f.name || 'PAC file')} (ID ${_dfE(f.id)}) · ${_dfE(f.url || 'URL unavailable')} · ${f.has_content ? 'content read' : 'content unverified'}</li>`).join('');
  return `<details><summary>Tenant profile and PAC inventory</summary><p>Configuration candidates; device assignment is not established.</p><h2 class="df-h">All app profiles</h2><ul>${apps}</ul><h2 class="df-h">All forwarding profiles</h2><ul>${forwarding}</ul><h2 class="df-h">PAC files</h2><ul>${pac}</ul>${(c.errors || []).map(e => `<p>${_dfE(e)}</p>`).join('')}</details>`;
}
function renderDataFlowTrace(t, container) {
  const [olab, ocls] = DF_OUTCOME[t.outcome] || [t.outcome, 'dim'];
  const chans = Object.entries(t.channels || {}).map(([k, c]) => {
    const [lab, cls] = DF_STATUS[c.status] || [c.status, 'dim'];
    return `<div class="df-chan st-${cls}"><div class="df-hop-h"><span class="df-chip st-${cls}">${_dfE(lab)}</span><strong>${_dfE(c.label)}</strong></div><div class="df-hop-d">${_dfE(c.detail)}</div>${c.rules && c.rules.length ? `<div class="df-hop-d">Configured rules: ${_dfE(c.rules.join(', '))}</div>` : ''}${c.weak_point ? `<div class="df-weak sev-${_dfE(c.weak_point.severity)}"><span class="sev">${_dfE(c.weak_point.severity)}</span> <strong>${_dfE(c.weak_point.title)}</strong> — ${_dfE(c.weak_point.fix)}</div>` : ''}</div>`;
  }).join('');
  const packs = (t.packs || []).map(p => {
    const rows = p.rules.map(r => `<span class="df-rule st-${{ enforcing: 'ok', monitoring: 'warn', disabled: 'dim', missing: 'fail' }[r.state] || 'dim'}${r.on_path ? ' on' : ''}" title="${_dfE(r.channel)} · ${_dfE(r.state)}${r.on_path ? ' · on this path' : ''}">${_dfE(r.name)}</span>`).join('');
    return `<div class="df-pack cov-${_dfE(p.coverage)}"><div class="df-hop-h"><span class="df-chip st-${{ enforcing: 'ok', monitoring: 'warn', partial: 'warn', deployed: 'dim', missing: 'fail' }[p.coverage] || 'dim'}">${_dfE(p.coverage)}</span><strong>${_dfE(p.name)}</strong>${p.weak_point ? `<span class="df-by">${_dfE(p.weak_point)}</span>` : ''}</div><div class="df-rules-wrap">${rows}</div></div>`;
  }).join('');
  const weak = (t.weak_points || []).map(w => `<li class="sev-${_dfE(w.severity)}"><span class="sev">${_dfE(w.severity)}</span> <strong>${_dfE(w.title)}</strong> <span class="df-by">at ${_dfE(w.hop_label)}</span><div class="df-hop-d">${_dfE(w.fix)}</div></li>`).join('');
  const zccHop = (t.hops || []).find(h => h.key === 'zcc');
  const fwdHop = (t.hops || []).find(h => h.key === 'forwarding');
  const appProf = (zccHop && zccHop.decided_by && zccHop.decided_by.name) || (zccHop && zccHop.profile) || '—';
  const fwdProf = (fwdHop && fwdHop.decided_by && fwdHop.decided_by.name) || '—';
  const fwdMode = (fwdHop && fwdHop.mode) ? ` (${_dfE(fwdHop.mode)})` : '';
  container.innerHTML = `
    ${connectorInventoryHtml(t.connector_inventory)}
    <div class="df-outcome st-${ocls}"><span class="df-chip st-${ocls}">${_dfE(olab)}</span><strong>${_dfE(t.destination.label)}</strong> <span class="df-by">${_dfE(t.destination.kind)}${t.destination.categories && t.destination.categories.length ? ` · categories ${_dfE(t.destination.categories.slice(0, 4).join(', '))}` : ''}${t.destination.applications && t.destination.applications.length ? ` · ${t.destination.applications.length} application(s)` : ''}</span></div>
    <div class="df-profiles">
      <span class="df-prof"><span class="k">Client Connector app profile</span><span class="v">${_dfE(appProf)}</span></span>
      <span class="df-prof"><span class="k">Forwarding profile</span><span class="v">${_dfE(fwdProf)}${fwdMode}</span></span>
      <span class="df-prof"><span class="k">Network</span><span class="v">${_dfE(t.network)}</span></span>
      <span class="df-prof"><span class="k">Platform</span><span class="v">${_dfE(t.platform)}</span></span>
    </div>
    <div class="df-flow-wrap" id="dfFlowWrap">${_dfSvg(t)}</div>
    <div class="df-hint">Each box is a data security control on the path, in the order ZIA applies them; a dot marks a weak point. Click a box for the rule that decided it. SSL Inspection, Cloud App Control, URL Filtering and File Type Control are data security controls alongside DLP — they stop or scope data movement before content inspection; Cloud App Control runs with URL Filtering ahead of SSL inspection, takes precedence when it matches, and can gate on a user risk profile. Controls that are not data-leak controls (browser/FTP, threat protection, bandwidth, firewall) are left out here; the reference diagram above shows the full order. The last hop is what happens after a match: logs, the Incident Receiver and Workflow Automation.</div>
    <h2 class="df-h">Hops</h2>
    <div class="df-hops">${t.hops.map(_dfHopDetail).join('')}</div>
    <h2 class="df-h">Separate-channel inventory (not tested on this path)</h2>
    <div class="df-chans">${chans}</div>
    <h2 class="df-h">Policy packs on this path</h2>
    ${packs || '<div class="df-hop-d">No policy packs installed.</div>'}
    <h2 class="df-h">Weak points, worst first</h2>
    ${weak ? `<ul class="df-weaks">${weak}</ul>` : '<div class="df-hop-d">None on this path.</div>'}`;
  container.querySelectorAll('.df-node').forEach(n => n.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); n.dispatchEvent(new Event('click')); } }));
  container.querySelectorAll('.df-node').forEach(n => n.addEventListener('click', () => {
    const el = container.querySelector(`.df-hop[data-hop="${n.dataset.hop}"]`) || [...container.querySelectorAll('.df-hop')].find(x => x.textContent.includes(n.getAttribute('aria-label').split(':')[0]));
    if (el) el.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }));
}

function renderDataFlowOverview(report, container) {
  const rows = report.traces.map((t, i) => {
    const [olab, ocls] = DF_OUTCOME[t.outcome] || [t.outcome, 'dim'];
    const net = (report.networks.find(n => n.key === t.network) || {}).label || t.network;
    const high = t.weak_points.filter(w => w.severity === 'high').length;
    return `<tr class="df-row" id="dfRow-${i}" data-i="${i}" tabindex="0"><td>${_dfE(t.destination.label)}</td><td>${_dfE(net)}</td><td><span class="df-chip st-${ocls}">${_dfE(olab)}</span></td><td>${t.hops.filter(h => h.status === 'bypass').length ? 'client / PAC' : (t.conditional || (t.hops || []).some(h => h.key === 'ssl' && ['unknown', 'out_of_scope', 'conditional'].includes(h.status)) ? 'unverified' : t.decrypted ? 'decrypted' : 'encrypted')}</td><td>${high ? `<span class="df-chip st-fail">${high} high</span>` : (t.weak_points.length ? `<span class="df-chip st-warn">${t.weak_points.length}</span>` : '<span class="df-chip st-ok">0</span>')}</td></tr>`;
  }).join('');
  container.innerHTML = `<div class="df-tablewrap"><table class="df-table"><thead><tr><th>Destination</th><th>Network</th><th>Outcome</th><th>Visibility</th><th>Weak points</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

// Visibility across each cloud app category: for every destination class
// (AI/ML, webmail, file sharing, …) on every network, is the traffic
// bypassed (no visibility), reaching ZIA encrypted (blind), or decrypted
// and inspected — and if inspected, enforced or monitor-only.
function _dfVisibility(t) {
  if (t.outcome === 'blocked') return ['Blocked', 'block', 'Stopped before downstream inspection; no content scan established'];
  if (t.conditional || t.policy_conditional || (t.hops || []).some(h => h.key === 'ssl' && ['unknown', 'out_of_scope', 'conditional'].includes(h.status))) return ['Unable to verify', 'dim', 'Routing or inspection evidence is unavailable or outside scope'];
  if (!t.reaches_zscaler) return ['Bypassed', 'fail', 'Leaves the device direct — no cloud visibility'];
  if (!t.decrypted) return ['Encrypted', 'warn', 'Reaches ZIA but is not decrypted — inline DLP is blind'];
  if (t.outcome === 'enforce') return ['Decryption configured · enforce', 'ok', 'Configuration permits content inspection; no payload was scanned'];
  if (t.outcome === 'monitor') return ['Decryption configured · monitor', 'warn', 'Monitoring configuration; no payload was scanned'];
  return ['Decryption configured', 'dim', 'No content inspection was observed'];
}

function renderCategoryVisibility(report, container) {
  const cats = report.traces.filter(t => t.destination && t.destination.kind === 'class');
  if (!cats.length) { container.innerHTML = '<div class="df-hop-d">No cloud app categories traced.</div>'; return; }
  const nets = report.networks.map(n => n.key);
  const netLabel = k => (report.networks.find(n => n.key === k) || {}).label || k;
  const byCat = {};
  cats.forEach(t => { const c = t.destination.label; (byCat[c] = byCat[c] || {})[t.network] = t; });
  const head = `<tr><th>Cloud app category</th>${nets.map(n => `<th>${_dfE(netLabel(n))}</th>`).join('')}</tr>`;
  const rows = Object.keys(byCat).sort().map(c => {
    const cells = nets.map(n => {
      const t = byCat[c][n];
      if (!t) return '<td><span class="df-chip st-dim">—</span></td>';
      const [lab, cls, tip] = _dfVisibility(t);
      const i = report.traces.indexOf(t);
      return `<td><button type="button" class="df-vis df-vis-${cls}" data-i="${i}" title="${_dfE(tip)} — click for the path">${_dfE(lab)}</button></td>`;
    }).join('');
    return `<tr><td class="df-vis-cat">${_dfE(c)}</td>${cells}</tr>`;
  }).join('');
  container.innerHTML = `<div class="df-tablewrap"><table class="df-table df-vis-table"><thead>${head}</thead><tbody>${rows}</tbody></table></div>
    <div class="df-hint">Each cell is the visibility for that category on that network. Click a cell to jump to its path.</div>`;
}

// Where inspection is lost: every path that never reaches Zscaler
// (bypassed at the client or forwarding) or reaches it encrypted (blind),
// with the rule/profile that decided it — the bypass + SSL gaps in one place.
function renderDataFlowGaps(report, container) {
  const netLabel = k => (report.networks.find(n => n.key === k) || {}).label || k;
  const lost = report.traces.filter(t => t.outcome !== 'blocked' && !t.conditional && !t.policy_conditional && !(t.hops || []).some(h => h.key === 'ssl' && ['unknown', 'out_of_scope', 'conditional'].includes(h.status)) && (!t.reaches_zscaler || !t.decrypted)).map((t, _i) => ({ t, i: report.traces.indexOf(t) }));
  if (!lost.length && report.traces.some(t => t.conditional || t.policy_conditional || (t.hops || []).some(h => h.key === 'ssl' && ['unknown', 'out_of_scope', 'conditional'].includes(h.status)))) { container.innerHTML = '<p>Routing or inspection remains unverified; no confirmed visibility gap can be inferred.</p>'; return; }
  if (!lost.length) { container.innerHTML = '<div class="df-hop-d">No confirmed bypass or SSL visibility gap was identified. Blocked paths are not inspection failures.</div>'; return; }
  const bypassed = lost.filter(x => !x.t.reaches_zscaler);
  const blind = lost.filter(x => x.t.reaches_zscaler && !x.t.decrypted);
  const item = ({ t, i }) => {
    const hop = (t.hops || []).find(h => h.status === 'bypass') || (t.hops || []).find(h => h.key === 'ssl') || {};
    const by = (hop.decided_by && hop.decided_by.name) || hop.profile || '';
    return `<button type="button" class="df-gap" data-i="${i}"><span class="df-gap-d">${_dfE(t.destination.label)}</span><span class="df-gap-n">${_dfE(netLabel(t.network))}</span><span class="df-gap-w">${_dfE(hop.detail || '')}${by ? ` <em>(${_dfE(by)})</em>` : ''}</span></button>`;
  };
  container.innerHTML =
    (bypassed.length ? `<div class="df-gap-h st-fail">Never reaches Zscaler — no cloud visibility (${bypassed.length})</div><div class="df-gaps">${bypassed.map(item).join('')}</div>` : '') +
    (blind.length ? `<div class="df-gap-h st-warn">Reaches ZIA encrypted — inline DLP is blind (${blind.length})</div><div class="df-gaps">${blind.map(item).join('')}</div>` : '');
}

// ── Control flow by category ──────────────────────────────────────
// One left-to-right flow per cloud app category, in the same style as the
// path above: device -> Client Connector -> forwarding -> Cloud App
// Control -> URL Filtering -> SSL -> File Type Control -> DLP -> logs &
// incidents, each hop the data security control that decides it. Click a
// category to open its path.
function renderControlFishbones(report, container, network) {
  const net = network || (report.traces[0] && report.traces[0].network);
  const cats = report.traces.filter(t => t.destination && t.destination.kind === 'class' && t.network === net);
  if (!cats.length) { container.innerHTML = '<div class="df-hop-d">No cloud app categories traced for this network.</div>'; return; }
  const netLabel = (report.networks.find(n => n.key === net) || {}).label || net;
  const cards = cats.map(t => {
    const [olab, ocls] = DF_OUTCOME[t.outcome] || [t.outcome, 'dim'];
    // The whole card is the click target, so the diagram's own nodes are
    // drawn non-interactive here (no nested buttons).
    const svg = _dfSvg(t).replace(/ tabindex="0" role="button"/g, '');
    return `<button type="button" class="df-cat-card" data-i="${report.traces.indexOf(t)}" aria-label="Open the full path for ${_dfE(t.destination.label)}: ${_dfE(olab)}">
      <div class="df-cat-h"><strong>${_dfE(t.destination.label)}</strong><span class="df-chip st-${ocls}">${_dfE(olab)}</span></div>
      ${svg}</button>`;
  }).join('');
  container.innerHTML = `<div class="df-hint">One flow per cloud app category on <strong>${_dfE(netLabel)}</strong>, in the order ZIA applies it: each hop is the data security control that decides it — Cloud App Control (before URL Filtering), URL Filtering, SSL Inspection, File Type Control and DLP, then what happens after a match. Cloud App Control and URL Filtering can also gate on a user risk profile. Click a category to open its full path.</div>
    <div class="df-cat-grid">${cards}</div>`;
}

// ── Traffic flow motion (static/flow_anim.js) ─────────────────────
// Every traced path as a packet stream through the hops the tracer
// walked, each stream as wide as its share of the paths. Hover or focus a
// stream for its count; its paths link to their rows in "Every
// destination, every network". Built with DOM calls (textContent only):
// destination names are tenant data. Returns the picture (play, pause,
// running, destroy) or null without the motion module.
function renderDataFlowMotion(report, container, onRow) {
  const FA = window.FA;
  container.textContent = '';
  if (!FA || !FA.dataFlowModel) return null;
  const m = FA.dataFlowModel(report);
  if (!m || !m.total) { const p = document.createElement('p'); p.className = 'df-hop-d'; p.textContent = 'No path was traced, so there is no traffic to draw.'; container.appendChild(p); return null; }
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const wrap = el('div', 'fa-motion');
  wrap.appendChild(el('p', 'fa-lead', `Each stream is one route through the hops, as wide as its share of the ${m.total} traced paths (every traffic class on every network); packets move along it, coloured by where their path ends (green: decrypted with a DLP rule that can block, amber: monitor only or unverified, red: bypassed, left encrypted or blocked; a cross marks where a bypass leaves the flow). Hover or focus a stream for its count, and press Enter to list its paths.`));
  const bar = el('div', 'fa-motion-bar');
  const btn = el('button', 'rp-btn'); btn.type = 'button'; btn.id = 'dfMotionPlay';
  bar.appendChild(btn); wrap.appendChild(bar);
  if (m.mismatch.length) wrap.appendChild(el('p', 'fa-warnline', `The picture and the summary disagree (${m.mismatch.join('; ')}); trust the summary numbers below.`));
  const stage = el('div', 'fa-stage'); stage.id = 'dfMotionStage';
  wrap.appendChild(stage);
  const pick = el('div', 'fa-pick'); pick.id = 'dfMotionPick'; pick.setAttribute('role', 'status'); pick.setAttribute('aria-live', 'polite');
  pick.textContent = 'Hover or focus a stream to see how many paths take it.';
  wrap.appendChild(pick);
  wrap.appendChild(el('h3', 'df-h', 'In words'));
  container.appendChild(wrap);
  FA.altList(wrap, m.alt, 'dfMotionAlt');
  // The stream last opened with Enter or a click stays listed (its links
  // keep focus) until another is opened.
  let held = null, current = '';
  const show = (l, list) => {
    if (!l && held) { l = held; list = true; }
    const now = l ? l.key + (list ? '+' : '') : '';
    if (now === current) return;
    current = now;
    pick.textContent = '';
    if (!l) { pick.textContent = 'Hover or focus a stream to see how many paths take it.'; return; }
    pick.appendChild(el('strong', '', l.label));
    if (!list) return;
    const ul = el('ul', '');
    l.items.forEach(it => {
      const li = el('li', ''), a = el('a', '', it.name);
      a.href = `#dfRow-${it.i}`;
      a.addEventListener('click', ev => { ev.preventDefault(); if (onRow) onRow(it.i); });
      li.appendChild(a); ul.appendChild(li);
    });
    pick.appendChild(ul);
  };
  const pic = FA.river(stage, m, {
    height: 220,
    onFocus: l => show(l, false),
    onPick: l => { held = l; show(l, true); const a = pick.querySelector('a'); if (a) a.focus(); },
  });
  pic.svg.setAttribute('aria-describedby', 'dfMotionAlt');
  FA.playButton(btn, () => [pic]);
  return pic;
}

window.renderDataFlowMotion = renderDataFlowMotion;
window.renderPolicyEnforcementFlow = renderPolicyEnforcementFlow;
window.renderDataFlowTrace = renderDataFlowTrace;
window.renderDataFlowOverview = renderDataFlowOverview;
window.renderCategoryVisibility = renderCategoryVisibility;
window.renderDataFlowGaps = renderDataFlowGaps;
window.renderControlFishbones = renderControlFishbones;
