// ── Data Flow Map renderer ──────────────────────────────────────────
// Draws one traced path as a row of hops (device → Client Connector →
// forwarding → PAC → SSL → URL → app control → file type → Web DLP) with
// the parallel channels beneath, the weak points ranked, and every policy
// pack's coverage on that path. Pure DOM; data comes from
// /api/report/data-flow. Also used by the assessment page's mirror.
const _dfE = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const DF_STATUS = {
  pass: ['Forwarded', 'ok'], enforce: ['Enforcing', 'ok'], blocked: ['Blocked', 'block'], monitor: ['Monitor only', 'warn'],
  warn: ['Weak', 'warn'], blind: ['Encrypted / blind', 'fail'], bypass: ['Bypassed', 'fail'], none: ['No control', 'warn'],
  unknown: ['Could not read', 'dim'], skipped: ['Not reached', 'dim'], off: ['Not active', 'fail'],
};
const DF_OUTCOME = {
  bypassed: ['Never reaches Zscaler', 'fail'], blocked: ['Blocked before content', 'block'], blind: ['Reaches ZIA encrypted: DLP blind', 'fail'],
  enforce: ['Inspected and enforced', 'ok'], monitor: ['Inspected, monitor only', 'warn'], none: ['Inspected, no DLP rule', 'warn'],
};
const DF_HOP_ORDER = ['device', 'zcc', 'forwarding', 'pac', 'ssl', 'url', 'cac', 'ftc', 'dlp'];

function _dfSvg(t) {
  const hops = [{ key: 'device', label: 'Device', status: 'pass', detail: `${t.platform}, ${t.network}` }].concat(t.hops.filter(h => h.key !== 'zia'));
  const W = 168, H = 62, GAP = 34, PAD = 14, TOP = 30;
  const width = PAD * 2 + hops.length * W + (hops.length - 1) * GAP;
  const height = TOP + H + PAD + 10;
  let out = '';
  hops.forEach((h, i) => {
    const x = PAD + i * (W + GAP), y = TOP;
    const [lab, cls] = DF_STATUS[h.status] || [h.status, 'dim'];
    const name = h.decided_by && h.decided_by.name ? h.decided_by.name : (h.mode || h.profile || '');
    if (i > 0) {
      const px = x - GAP, cy = y + H / 2;
      const prev = hops[i - 1];
      const dead = prev.status === 'bypass' || prev.status === 'blocked' || h.status === 'skipped';
      out += `<path class="df-edge ${dead ? 'dead' : ''}" d="M${px},${cy} C${px + GAP * 0.5},${cy} ${x - GAP * 0.5},${cy} ${x},${cy}"/>`;
    }
    out += `<g class="df-node st-${cls}" data-hop="${_dfE(h.key)}" transform="translate(${x},${y})" tabindex="0" role="button" aria-label="${_dfE(h.label)}: ${_dfE(lab)}">
      <rect class="box" width="${W}" height="${H}" rx="12"/><rect class="bar" x="6" y="6" width="4" height="${H - 12}" rx="2"/>
      <text class="kind" x="18" y="17">${_dfE(h.label.toUpperCase())}</text>
      <text class="st" x="18" y="35">${_dfE(lab)}</text>
      <text class="sub" x="18" y="51">${_dfE((name || h.detail || '').slice(0, 26))}${(name || h.detail || '').length > 26 ? '…' : ''}</text>
      ${h.weak_point ? `<circle class="dot sev-${_dfE(h.weak_point.severity)}" cx="${W - 12}" cy="12" r="5"><title>${_dfE(h.weak_point.title)}</title></circle>` : ''}
    </g>`;
  });
  return `<svg class="df-svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="Path from the device to the destination">${out}</svg>`;
}

function _dfHopDetail(h) {
  const [lab, cls] = DF_STATUS[h.status] || [h.status, 'dim'];
  return `<div class="df-hop st-${cls}">
    <div class="df-hop-h"><span class="df-chip st-${cls}">${_dfE(lab)}</span><strong>${_dfE(h.label)}</strong>${h.decided_by && h.decided_by.name ? `<span class="df-by">decided by <code>${_dfE(h.decided_by.name)}</code>${h.decided_by.order != null ? ` (order ${_dfE(h.decided_by.order)})` : ''}</span>` : ''}</div>
    <div class="df-hop-d">${_dfE(h.detail)}</div>
    ${h.rules && h.rules.length ? `<ul class="df-rules">${h.rules.map(r => `<li><code>${_dfE(r.name)}</code> ${_dfE(r.action)}${r.enforcing ? ' · enforcing' : ' · monitor'}${r.engines && r.engines.length ? ` · engines: ${_dfE(r.engines.slice(0, 4).join(', '))}${r.engines.length > 4 ? '…' : ''}` : ''}</li>`).join('')}</ul>` : ''}
    ${h.actions && h.actions.length ? `<div class="df-hop-d">Actions: ${_dfE(h.actions.join(', '))}</div>` : ''}
    ${h.raw ? `<div class="df-raw">raw: ${_dfE(JSON.stringify(h.raw))}</div>` : ''}
    ${h.weak_point ? `<div class="df-weak sev-${_dfE(h.weak_point.severity)}"><span class="sev">${_dfE(h.weak_point.severity)}</span> <strong>${_dfE(h.weak_point.title)}</strong> — ${_dfE(h.weak_point.fix)}</div>` : ''}
  </div>`;
}

function renderDataFlowTrace(t, container) {
  const [olab, ocls] = DF_OUTCOME[t.outcome] || [t.outcome, 'dim'];
  const chans = Object.entries(t.channels || {}).map(([k, c]) => {
    const [lab, cls] = DF_STATUS[c.status] || [c.status, 'dim'];
    return `<div class="df-chan st-${cls}"><div class="df-hop-h"><span class="df-chip st-${cls}">${_dfE(lab)}</span><strong>${_dfE(c.label)}</strong></div><div class="df-hop-d">${_dfE(c.detail)}</div>${c.weak_point ? `<div class="df-weak sev-${_dfE(c.weak_point.severity)}"><span class="sev">${_dfE(c.weak_point.severity)}</span> <strong>${_dfE(c.weak_point.title)}</strong> — ${_dfE(c.weak_point.fix)}</div>` : ''}</div>`;
  }).join('');
  const packs = (t.packs || []).map(p => {
    const rows = p.rules.map(r => `<span class="df-rule st-${{ enforcing: 'ok', monitoring: 'warn', disabled: 'dim', missing: 'fail' }[r.state] || 'dim'}${r.on_path ? ' on' : ''}" title="${_dfE(r.channel)} · ${_dfE(r.state)}${r.on_path ? ' · on this path' : ''}">${_dfE(r.name)}</span>`).join('');
    return `<div class="df-pack cov-${_dfE(p.coverage)}"><div class="df-hop-h"><span class="df-chip st-${{ enforcing: 'ok', monitoring: 'warn', partial: 'warn', deployed: 'dim', missing: 'fail' }[p.coverage] || 'dim'}">${_dfE(p.coverage)}</span><strong>${_dfE(p.name)}</strong>${p.weak_point ? `<span class="df-by">${_dfE(p.weak_point)}</span>` : ''}</div><div class="df-rules-wrap">${rows}</div></div>`;
  }).join('');
  const weak = (t.weak_points || []).map(w => `<li class="sev-${_dfE(w.severity)}"><span class="sev">${_dfE(w.severity)}</span> <strong>${_dfE(w.title)}</strong> <span class="df-by">at ${_dfE(w.hop_label)}</span><div class="df-hop-d">${_dfE(w.fix)}</div></li>`).join('');
  container.innerHTML = `
    <div class="df-outcome st-${ocls}"><span class="df-chip st-${ocls}">${_dfE(olab)}</span><strong>${_dfE(t.destination.label)}</strong> <span class="df-by">${_dfE(t.destination.kind)}${t.destination.categories && t.destination.categories.length ? ` · categories ${_dfE(t.destination.categories.slice(0, 4).join(', '))}` : ''}${t.destination.applications && t.destination.applications.length ? ` · ${t.destination.applications.length} application(s)` : ''}</span></div>
    <div class="df-flow-wrap" id="dfFlowWrap">${_dfSvg(t)}</div>
    <div class="df-hint">Each box is a hop the tenant's configuration puts on the path; a dot marks a weak point. Click a box for the rule that decided it.</div>
    <h3 class="df-h">Hops</h3>
    <div class="df-hops">${t.hops.map(_dfHopDetail).join('')}</div>
    <h3 class="df-h">Channels that do not ride the tunnel</h3>
    <div class="df-chans">${chans}</div>
    <h3 class="df-h">Policy packs on this path</h3>
    ${packs || '<div class="df-hop-d">No policy packs installed.</div>'}
    <h3 class="df-h">Weak points, worst first</h3>
    ${weak ? `<ul class="df-weaks">${weak}</ul>` : '<div class="df-hop-d">None on this path.</div>'}`;
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
    return `<tr class="df-row" data-i="${i}" tabindex="0"><td>${_dfE(t.destination.label)}</td><td>${_dfE(net)}</td><td><span class="df-chip st-${ocls}">${_dfE(olab)}</span></td><td>${t.hops.filter(h => h.status === 'bypass').length ? 'client / PAC' : (t.decrypted ? 'decrypted' : 'encrypted')}</td><td>${high ? `<span class="df-chip st-fail">${high} high</span>` : (t.weak_points.length ? `<span class="df-chip st-warn">${t.weak_points.length}</span>` : '<span class="df-chip st-ok">0</span>')}</td></tr>`;
  }).join('');
  container.innerHTML = `<div class="df-tablewrap"><table class="df-table"><thead><tr><th>Destination</th><th>Network</th><th>Outcome</th><th>Visibility</th><th>Weak points</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

window.renderDataFlowTrace = renderDataFlowTrace;
window.renderDataFlowOverview = renderDataFlowOverview;
