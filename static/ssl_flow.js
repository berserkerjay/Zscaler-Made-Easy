// SSL Inspection Flow renderer: a live, three-column flow diagram
// (traffic class → SSL inspection decision → inline Web DLP outcome) with
// the gaps highlighted, plus the gap list and the rule tables. Used by
// the standalone /report/sslflow tab. No dependencies.
function _sfE(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
const SF = { data: null, selected: null, container: null };

const SF_DECISION = {
  inspected:     { label: 'DECRYPTED',     cls: 'ok',   hint: 'SSL inspection opens this traffic; inline DLP can read the content.' },
  not_inspected: { label: 'NOT DECRYPTED', cls: 'bad',  hint: 'A Do-Not-Decrypt rule matches first; inline DLP never sees the content.' },
  no_rule:       { label: 'NO RULE',       cls: 'bad',  hint: 'No SSL rule matches, so the traffic passes through encrypted.' },
  blocked:       { label: 'BLOCKED',       cls: 'mute', hint: 'Blocked at SSL inspection; nothing leaves, nothing to inspect.' },
};
const SF_DLP = {
  enforcing: { label: 'DLP enforcing',        cls: 'ok' },
  monitor:   { label: 'DLP monitor only',     cls: 'warn' },
  none:      { label: 'No inline DLP rule',   cls: 'warn' },
  blind:     { label: 'DLP blind (encrypted)', cls: 'bad' },
  blocked:   { label: 'Traffic blocked',      cls: 'mute' },
};
const SF_REL = { high: 'HIGH', medium: 'MEDIUM', privacy: 'PRIVACY', low: 'LOW' };

function _sfWorst(c) {
  const order = ['high', 'medium', 'low', 'info'];
  let worst = null;
  for (const g of c.gaps || []) if (worst === null || order.indexOf(g.severity) < order.indexOf(worst)) worst = g.severity;
  return worst;
}
function _sfTrim(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; }

function _sfSvg(data) {
  const E = _sfE;
  const classes = data.classes || [];
  const W = { a: 268, b: 236, c: 250 }, GAP = 78, ROW = 64, PAD = 16, TOP = 42, H = 50;
  const xA = PAD, xB = xA + W.a + GAP, xC = xB + W.b + GAP;
  const width = xC + W.c + PAD, height = TOP + (classes.length + 1) * ROW + PAD;
  const head = (x, w, t) => `<text class="sf-head" x="${x + w / 2}" y="${TOP - 18}" text-anchor="middle">${E(t)}</text>`;
  let edges = '', nodes = '';
  // Row 0: traffic that bypasses Client Connector never reaches Zscaler at all.
  const zcc = data.zcc || {};
  const zTotal = zcc.total || 0;
  {
    const y = TOP, cy = y + H / 2;
    const cls = zcc.available ? (zTotal ? 'bad' : 'ok') : 'mute';
    const curve = (x1, x2, k) => { const dx = (x2 - x1) * 0.5; return `<path class="sf-edge ${k}" d="M${x1},${cy} C${x1 + dx},${cy} ${x2 - dx},${cy} ${x2},${cy}"/>`; };
    edges += curve(xA + W.a, xB, zTotal ? 'bad' : 'mute') + curve(xB + W.b, xC, zTotal ? 'bad' : 'mute');
    const cc = zcc.counts || {};
    const meta = zcc.available ? `${cc.apps || 0} apps · ${cc.domains || 0} domains · ${cc.ips || 0} IPs · ${cc.trusted_networks || 0} trusted nets` : 'Client Connector profiles not readable';
    nodes += `<g class="sf-node sev-${zTotal ? 'high' : 'none'}${SF.selected === 'zcc' ? ' is-sel' : ''}" data-key="zcc" transform="translate(${xA},${y})" tabindex="0" role="button" aria-label="Client Connector bypasses">
      <rect class="box" width="${W.a}" height="${H}" rx="10"/><rect class="bar" x="0" y="0" width="4" height="${H}" rx="2"/>
      <text class="name" x="14" y="21">Bypasses Client Connector</text><text class="sub" x="14" y="38">${E(meta)}</text>
      ${zTotal ? `<g transform="translate(${W.a - 46},-8)"><rect class="sf-badge high" width="44" height="16" rx="8"/><text class="sf-badge-t" x="22" y="11.5" text-anchor="middle">GAP</text></g>` : ''}</g>`;
    nodes += `<g class="sf-node dec-${cls}${SF.selected === 'zcc' ? ' is-sel' : ''}" data-key="zcc" transform="translate(${xB},${y})" tabindex="0" role="button">
      <rect class="box" width="${W.b}" height="${H}" rx="10"/><rect class="bar" x="0" y="0" width="4" height="${H}" rx="2"/>
      <text class="st" x="14" y="20">${zTotal ? 'NEVER REACHES ZSCALER' : (zcc.available ? 'NO BYPASSES' : 'UNKNOWN')}</text><text class="sub" x="14" y="37">${zTotal ? `${zTotal} bypass entr${zTotal === 1 ? 'y' : 'ies'} in ${zcc.profiles || 0} profile(s)` : (zcc.available ? 'every device sends traffic through ZIA' : 'read the Bypass report')}</text></g>`;
    nodes += `<g class="sf-node dec-${cls}${SF.selected === 'zcc' ? ' is-sel' : ''}" data-key="zcc" transform="translate(${xC},${y})" tabindex="0" role="button">
      <rect class="box" width="${W.c}" height="${H}" rx="10"/><rect class="bar" x="0" y="0" width="4" height="${H}" rx="2"/>
      <text class="st" x="14" y="20">${zTotal ? 'DLP blind (bypassed)' : (zcc.available ? 'Nothing bypassed' : 'Unknown')}</text><text class="sub" x="14" y="37">${zTotal ? 'no SSL rule, no DLP rule ever sees it' : ''}</text></g>`;
  }
  classes.forEach((c, i0) => {
    const i = i0 + 1;
    const y = TOP + i * ROW, cy = y + H / 2;
    const dec = SF_DECISION[c.decision] || SF_DECISION.no_rule;
    const dlp = SF_DLP[c.dlp_status] || SF_DLP.none;
    const worst = _sfWorst(c);
    const sel = SF.selected === c.key ? ' is-sel' : '';
    const curve = (x1, x2, cls) => { const dx = (x2 - x1) * 0.5; return `<path class="sf-edge ${cls}" d="M${x1},${cy} C${x1 + dx},${cy} ${x2 - dx},${cy} ${x2},${cy}"/>`; };
    edges += curve(xA + W.a, xB, c.decision === 'inspected' ? 'flow' : c.decision === 'blocked' ? 'mute' : 'bad');
    edges += curve(xB + W.b, xC, c.decision === 'inspected' ? (c.dlp_status === 'enforcing' ? 'flow' : 'flow warn') : c.decision === 'blocked' ? 'mute' : 'bad');
    const d = c.decided_by || {};
    const ruleLine = d.name ? `${_sfTrim(d.name, 30)}${d.order != null ? ` · order ${d.order}` : ''}` : 'nothing matched';
    const dlpLine = c.dlp_status === 'blind' ? (c.dlp_rules.length ? `${c.dlp_rules.length} rule(s) cannot see content` : 'content is encrypted')
      : c.dlp_status === 'blocked' ? 'blocked before DLP'
      : c.dlp_rules.length ? _sfTrim(c.dlp_rules.map(r => r.name).join(', '), 34) : 'add a Web DLP rule';
    const meta = c.catch_all ? 'everything else (catch-all)' : `${c.url_categories.length} categor${c.url_categories.length === 1 ? 'y' : 'ies'}${c.application_count ? ` · ${c.application_count} apps` : ''}`;
    const gapBadge = worst && worst !== 'info' ? `<g transform="translate(${W.a - 46},-8)"><rect class="sf-badge ${worst}" width="44" height="16" rx="8"/><text class="sf-badge-t" x="22" y="11.5" text-anchor="middle">${worst === 'high' ? 'GAP' : worst === 'medium' ? 'CHECK' : 'TUNE'}</text></g>` : '';
    nodes += `<g class="sf-node sev-${worst || 'none'}${sel}" data-key="${E(c.key)}" transform="translate(${xA},${y})" tabindex="0" role="button" aria-label="${E(c.label)}: ${E(dec.label)}, ${E(dlp.label)}">
      <rect class="box" width="${W.a}" height="${H}" rx="10"/><rect class="bar" x="0" y="0" width="4" height="${H}" rx="2"/>
      <text class="name" x="14" y="21">${E(_sfTrim(c.label, 36))}</text>
      <text class="sub" x="14" y="38">${E(meta)} · <tspan class="rel">${E(SF_REL[c.relevance] || '')}</tspan></text>${gapBadge}</g>`;
    nodes += `<g class="sf-node dec-${dec.cls}${sel}" data-key="${E(c.key)}" transform="translate(${xB},${y})" tabindex="0" role="button" aria-label="${E(dec.hint)}">
      <rect class="box" width="${W.b}" height="${H}" rx="10"/><rect class="bar" x="0" y="0" width="4" height="${H}" rx="2"/>
      <text class="st" x="14" y="20">${E(dec.label)}</text><text class="sub" x="14" y="37">${E(ruleLine)}</text>
      ${c.exceptions && c.exceptions.length ? `<text class="pill" x="${W.b - 12}" y="20" text-anchor="end">${c.exceptions.length} exception${c.exceptions.length === 1 ? '' : 's'}</text>` : ''}</g>`;
    nodes += `<g class="sf-node dec-${dlp.cls}${sel}" data-key="${E(c.key)}" transform="translate(${xC},${y})" tabindex="0" role="button" aria-label="${E(dlp.label)}">
      <rect class="box" width="${W.c}" height="${H}" rx="10"/><rect class="bar" x="0" y="0" width="4" height="${H}" rx="2"/>
      <text class="st" x="14" y="20">${E(dlp.label)}</text><text class="sub" x="14" y="37">${E(dlpLine)}</text></g>`;
  });
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="group" aria-label="SSL inspection flow">
    ${head(xA, W.a, 'TRAFFIC LEAVING USERS')}${head(xB, W.b, 'SSL INSPECTION DECIDES')}${head(xC, W.c, 'INLINE WEB DLP SEES')}
    <g class="sf-edges">${edges}</g><g class="sf-nodes">${nodes}</g></svg>`;
}

function _sfZccDetail(z) {
  const E = _sfE;
  const c = z.counts || {};
  const rows = (z.items || []).slice(0, 60).map(it => `<tr><td>${E(it.kind_label)}</td><td>${E(it.profile || '')}</td><td class="mono">${E(it.value || '')}</td><td class="dim">${E(it.detail || '')}</td></tr>`).join('');
  const gap = (SF.data.gaps || []).find(g => g.type === 'zcc_bypass');
  return `
    <div class="sf-detail-head"><div><div class="sf-detail-t">Bypasses Client Connector <span class="bp-chip">live</span></div>
      <div class="dim">App and forwarding profiles can send applications, processes, domains and IP ranges around the Zscaler tunnel, and trusted networks switch the tunnel off. That traffic never reaches ZIA: no SSL inspection rule and no inline DLP rule ever sees it, whatever the rows below say.</div></div>
      <div class="sf-detail-dec dec-${z.total ? 'bad' : (z.available ? 'ok' : 'mute')}">${z.total ? 'NEVER REACHES ZSCALER' : (z.available ? 'NO BYPASSES' : 'UNKNOWN')}<small>${z.available ? `${z.total} entr${z.total === 1 ? 'y' : 'ies'} across ${z.profiles || 0} profile(s)` : E(z.error || 'Client Connector profiles could not be read')}</small></div></div>
    <div class="sf-kvs"><div class="sf-kv"><div class="k">Counts</div><div class="v">${['apps', 'processes', 'domains', 'ips', 'trusted_networks'].map(k => `<span class="bp-code">${c[k] || 0} ${k.replace('_', ' ')}</span>`).join('')}</div></div>
      <div class="sf-kv"><div class="k">Full report</div><div class="v"><a class="rp-btn" href="#" id="sfOpenBypass">Open the Bypass &amp; Non-Inspected report in a new tab</a> <span class="dim">every SSL bypass, allow rule and Client Connector exemption, with exports</span></div></div></div>
    ${rows ? `<div class="bp-h">Bypass entries (${(z.items || []).length}${(z.items || []).length > 60 ? ', first 60 shown' : ''})</div><div class="max"><table class="bp-table"><thead><tr><th>Kind</th><th>Profile</th><th>Value</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table></div>` : (z.available ? '<div class="bp-none">No bypass entries in any profile.</div>' : '')}
    ${gap ? `<div class="bp-h">Gap</div><div class="bp-card risk"><div class="t"><span class="bp-chip act">high</span> ${E(gap.title)}</div><div>${E(gap.detail)}</div><div class="sf-fix"><b>Fix:</b> ${E(gap.fix)}</div></div>` : ''}`;
}
// The Bypass report needs tenant credentials, which only the assessment
// tab holds: open the report tab here (inside the click) and ask the
// opener to generate it.
async function _sfOpenBypass(ev) {
  ev.preventDefault();
  const op = window.opener;
  if (!op || op.closed || typeof op.__bypassGenerate !== 'function') { alert('Open the assessment tab and click Bypass / Non-Inspected there; this tab has no tenant credentials.'); return; }
  const w = window.open('/report/bypass?pending=1', '_blank');
  if (!w) return;
  try { const id = await op.__bypassGenerate(); w.location = `/report/bypass?id=${encodeURIComponent(id)}`; }
  catch (e) { w.location = `/report/bypass?error=${encodeURIComponent(e.message)}`; }
}
function _sfDetail(c) {
  const E = _sfE;
  if (c === 'zcc') return _sfZccDetail(SF.data.zcc || {});
  if (!c) return '<div class="sf-detail-empty">Click a row in the diagram to see which rule decides, who is exempt, which DLP rules apply and how to close the gap.</div>';
  const dec = SF_DECISION[c.decision] || SF_DECISION.no_rule;
  const d = c.decided_by;
  const rule = r => `<span class="sf-rule"><b>${E(r.name)}</b>${r.order != null ? ` <span class="dim">order ${E(r.order)}</span>` : ''} <span class="bp-chip act">${E(r.action || r.decision || '')}</span>${r.scope && r.scope.length ? ` <span class="dim">(${E(r.scope.join(', '))})</span>` : ''}${r.default_rule ? ' <span class="bp-chip">default rule</span>' : ''}</span>`;
  const list = (title, items, render) => items && items.length ? `<div class="sf-kv"><div class="k">${E(title)}</div><div class="v">${items.map(render).join('<br>')}</div></div>` : '';
  const gaps = (c.gaps || []).map(g => `<div class="bp-card ${g.severity === 'high' ? 'risk' : g.severity === 'medium' ? 'warn' : 'info'}"><div class="t"><span class="bp-chip ${g.severity === 'high' ? 'act' : ''}">${E(g.severity)}</span> ${E(g.title)}</div><div>${E(g.detail)}</div><div class="sf-fix"><b>Fix:</b> ${E(g.fix)}</div></div>`).join('');
  const dlpRows = (c.dlp_rules || []).map(r => `<tr><td class="mono">${E(r.id)}</td><td>${E(r.name)}</td><td><span class="bp-chip ${r.enforcing ? 'act' : ''}">${E(r.action)}</span></td><td>${r.catch_all ? 'all traffic' : 'this traffic'}</td><td>${(r.engines || []).length}</td><td class="dim">${r.without_content_inspection ? 'no content inspection' : ''}${r.scope && r.scope.length ? E(r.scope.join(', ')) : ''}</td></tr>`).join('');
  return `
    <div class="sf-detail-head"><div><div class="sf-detail-t">${E(c.label)} <span class="bp-chip">${E(SF_REL[c.relevance] || '')} relevance</span></div><div class="dim">${E(c.why)}</div></div>
      <div class="sf-detail-dec dec-${dec.cls}">${E(dec.label)}<small>${E(dec.hint)}</small></div></div>
    <div class="sf-kvs">
      <div class="sf-kv"><div class="k">Matched on</div><div class="v">${c.catch_all ? 'everything no other class claims (catch-all and default rules only)' : `${(c.url_category_names || []).map(n => `<span class="bp-code">${E(n)}</span>`).join('') || 'no URL categories'}${c.application_count ? ` <span class="dim">+ ${c.application_count} cloud apps of class ${E((c.app_classes || []).join(', '))}: ${E(c.applications.slice(0, 8).join(', '))}${c.application_count > 8 ? '…' : ''}</span>` : ''}`}</div></div>
      <div class="sf-kv"><div class="k">Decided by</div><div class="v">${d ? rule(d) : '<span class="dim">no enabled SSL rule matches this traffic</span>'}</div></div>
      ${list('Exceptions first (scoped rules)', c.exceptions, rule)}
      ${list('Shadowed decrypt rules', c.shadowed, rule)}
      ${list('Disabled decrypt rules', c.disabled_decrypt, rule)}
    </div>
    <div class="bp-h">Inline Web DLP rules that target this traffic (${(c.dlp_rules || []).length})</div>
    ${dlpRows ? `<div class="max"><table class="bp-table"><thead><tr><th>ID</th><th>Rule</th><th>Action</th><th>Scope</th><th>Engines</th><th>Notes</th></tr></thead><tbody>${dlpRows}</tbody></table></div>` : '<div class="bp-none">No enabled Web DLP rule targets this traffic.</div>'}
    <div class="bp-h">Gaps (${(c.gaps || []).length})</div>${gaps || '<div class="bp-none">Nothing to fix here.</div>'}`;
}

function _sfSelect(key) {
  SF.selected = key;
  const c = key === 'zcc' ? 'zcc' : (SF.data.classes || []).find(x => x.key === key);
  const det = document.getElementById('sfDetail');
  if (det) { det.innerHTML = _sfDetail(c); const b = document.getElementById('sfOpenBypass'); if (b) b.addEventListener('click', _sfOpenBypass); }
  document.querySelectorAll('.sf-node').forEach(n => n.classList.toggle('is-sel', n.dataset.key === key));
}

window.renderSslFlow = function renderSslFlow(data, container) {
  const E = _sfE;
  SF.data = data; SF.container = container;
  const s = data.summary || {};
  const gaps = data.gaps || [];
  const stat = (n, label, cls) => `<div class="sf-stat ${cls || ''}"><div class="n">${n || 0}</div><div class="k">${E(label)}</div></div>`;
  const diag = (data.diagnostics || []).length ? `<div class="bp-card warn"><div class="t">${data.diagnostics.length} source${data.diagnostics.length === 1 ? '' : 's'} could not be read fully</div><ul style="margin:0.3rem 0 0 1.1rem;font-size:0.8rem;color:var(--dim);">${data.diagnostics.map(d => `<li><strong>${E(d.section)}</strong>: <code>${E(d.error_type || '?')}</code> ${E(d.error || '')}</li>`).join('')}</ul></div>` : '';
  const ex = (data.zscaler_exemptions || []);
  const gapList = gaps.length ? gaps.map(g => `<li class="sev-${E(g.severity)}"><span class="bp-chip ${g.severity === 'high' ? 'act' : ''}">${E(g.severity)}</span><a href="#" data-class="${E(g.class)}" class="sf-gap-link">${E(g.title)}</a><span class="why">${E(g.detail)}<br><b>Fix:</b> ${E(g.fix)}</span></li>`).join('') : '<li class="sev-none"><span class="why">No gaps: every DLP-relevant traffic class is decrypted and covered by an inline DLP rule.</span></li>';
  const sslRows = (data.ssl_rules || []).map(r => {
    const targets = r.catch_all ? '<em>everything</em>' : r.zscaler_maintained ? '<em>Zscaler-maintained list</em>' : [...r.url_categories, ...r.cloud_applications].slice(0, 6).map(t => `<span class="bp-code">${E(t)}</span>`).join('') + ((r.url_categories.length + r.cloud_applications.length) > 6 ? ` +${r.url_categories.length + r.cloud_applications.length - 6}` : '') + (r.other_targets ? ` <span class="dim">+${r.other_targets} destination(s)</span>` : '');
    return `<tr class="${r.enabled ? '' : 'off'}"><td class="num">${E(r.order)}</td><td>${E(r.name)}${r.default_rule ? ' <span class="bp-chip">default</span>' : ''}${r.predefined && !r.default_rule ? ' <span class="bp-chip">predefined</span>' : ''}</td><td><span class="bp-chip ${r.decision === 'inspected' ? '' : 'act'}">${E(r.action)}</span></td><td>${E(r.state)}</td><td>${targets}</td><td class="dim">${E(r.scope.join(', ') || 'everyone')}</td></tr>`;
  }).join('');
  const dlpRows = (data.dlp_rules || []).map(r => `<tr class="${r.enabled ? '' : 'off'}"><td class="num">${E(r.order)}</td><td>${E(r.name)}</td><td><span class="bp-chip ${r.enforcing ? 'act' : ''}">${E(r.action)}</span></td><td>${E(r.state)}</td><td>${r.catch_all ? '<em>all traffic</em>' : [...r.url_categories, ...r.cloud_applications].slice(0, 6).map(t => `<span class="bp-code">${E(t)}</span>`).join('')}</td><td class="dim">${E(r.scope.join(', ') || 'everyone')}</td></tr>`).join('');
  container.innerHTML = `
    <div class="sf-hero">
      ${stat(s.inspected, 'classes decrypted', 'ok')}${stat(s.not_inspected, 'classes not decrypted', s.not_inspected ? 'bad' : '')}${stat(s.blocked, 'classes blocked', 'mute')}
      ${stat(s.dlp_covered, 'decrypted and DLP-covered', s.dlp_covered ? 'ok' : '')}${stat(s.zcc_bypasses || 0, 'Client Connector bypasses', (s.zcc_bypasses || 0) ? 'bad' : ((data.zcc || {}).available ? 'ok' : 'mute'))}${stat(s.gaps, 'gaps', s.high ? 'bad' : s.gaps ? 'warn' : 'ok')}${stat(s.high, 'high severity', s.high ? 'bad' : '')}
    </div>
    ${diag}
    <div class="sf-flow">
      <div class="sf-flow-bar">
        <div class="sf-legend"><span><i class="sw ok"></i>decrypted, DLP sees content</span><span><i class="sw warn"></i>decrypted, DLP gap</span><span><i class="sw bad"></i>encrypted, DLP blind</span><span><i class="sw mute"></i>blocked</span></div>
        <div class="dim" style="font-size:0.75rem;">${E(s.ssl_rules_enabled)} of ${E(s.ssl_rules)} SSL rules enabled · ${E(s.dlp_rules_enabled)} of ${E(s.dlp_rules)} Web DLP rules enabled</div>
      </div>
      <div class="sf-flow-wrap" id="sfFlowWrap">${_sfSvg(data)}</div>
      <div class="sf-hint">Top row: traffic that bypasses Client Connector and never reaches Zscaler (live from the app and forwarding profiles). Other rows are DLP-relevant traffic classes. Middle column: the first enabled SSL rule that matches (top-down, first match wins). Right column: what inline Web DLP can do with it. Click a row for the detail and the fix.</div>
    </div>
    <div class="sf-detail" id="sfDetail">${_sfDetail(null)}</div>
    <div class="bp-h">Gaps in relation to inline DLP (${gaps.length})</div>
    <ul class="bp-risks sf-gaps">${gapList}</ul>
    ${ex.length ? `<div class="bp-card info"><div class="t">Zscaler-maintained exemptions (${ex.length})</div><div class="dim">${ex.map(r => E(r.name)).join(', ')}: certificate-pinned applications Zscaler keeps out of inspection. Expected; leave enabled.</div></div>` : ''}
    <details class="bp-sec has-items"><summary>SSL inspection rules in evaluation order<span class="ct">${(data.ssl_rules || []).length}</span></summary><div><div class="max"><table class="bp-table"><thead><tr><th>Order</th><th>Rule</th><th>Action</th><th>State</th><th>Targets</th><th>Applies to</th></tr></thead><tbody>${sslRows || ''}</tbody></table></div></div></details>
    <details class="bp-sec has-items"><summary>Inline Web DLP rules<span class="ct">${(data.dlp_rules || []).length}</span></summary><div><div class="max"><table class="bp-table"><thead><tr><th>Order</th><th>Rule</th><th>Action</th><th>State</th><th>Targets</th><th>Applies to</th></tr></thead><tbody>${dlpRows || ''}</tbody></table></div></div></details>
    <div class="bp-card info bp-guide"><div class="t">How to read this</div><ul>${(data.guidance || []).map(g => `<li>${E(g)}</li>`).join('')}</ul></div>`;
  const wrap = document.getElementById('sfFlowWrap');
  wrap.addEventListener('click', ev => { const n = ev.target.closest('.sf-node'); if (n) _sfSelect(n.dataset.key); });
  wrap.addEventListener('keydown', ev => { const n = ev.target.closest('.sf-node'); if (n && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); _sfSelect(n.dataset.key); } });
  container.querySelectorAll('.sf-gap-link').forEach(a => a.addEventListener('click', ev => { ev.preventDefault(); _sfSelect(a.dataset.class); document.getElementById('sfDetail').scrollIntoView({ behavior: 'smooth', block: 'start' }); }));
  if (SF.selected) _sfSelect(SF.selected);
  else { const first = gaps.find(g => g.severity === 'high') || gaps[0]; if (first) _sfSelect(first.class); }
};
