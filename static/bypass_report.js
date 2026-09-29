// Bypass & non-inspected traffic report renderer. Used by the dialog in
// index.html and by the standalone /report/bypass tab. No dependencies.
function _bpE(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
window.renderBypassReport = function renderBypassReport(data, container) {
  const E = _bpE;
  const s = data.summary || {};
  const risks = data.risk_flags || [];
  const total = s.total_bypass_items || 0;
  const stat = (n, label, hot) => `<span class="bp-stat ${n ? (hot ? 'hot' : '') : 'zero'}"><b>${n || 0}</b>${E(label)}</span>`;
  const top = `
    <div class="bp-hero">
      <div class="bp-total ${risks.length ? 'risk' : (total ? '' : 'ok')}">
        <div class="n">${total}</div><div class="k">bypass items in this tenant</div>
        <div style="margin-top:0.5rem;font-size:0.82rem;color:${risks.length ? 'var(--fail)' : 'var(--dim)'};">${risks.length ? `${risks.length} high-risk` : 'no high-risk bypasses'}</div>
      </div>
      <div class="bp-groups">
        <div class="bp-group"><div class="t">SSL inspection</div><div class="bp-stats">${stat(s.ssl_bypass_rules, 'bypass rules', true)}${stat(s.ssl_exemptions, 'exemptions')}</div></div>
        <div class="bp-group"><div class="t">Policy allow rules</div><div class="bp-stats">${stat(s.url_filter_allow, 'URL')}${stat(s.firewall_allow, 'firewall')}${stat(s.dlp_allow, 'DLP', true)}</div></div>
        <div class="bp-group"><div class="t">Client Connector</div><div class="bp-stats">${stat(s.zcc_apps, 'apps')}${stat(s.zcc_processes, 'processes')}${stat(s.zcc_ips, 'IPs')}${stat(s.zcc_domains, 'domains')}${stat(s.zcc_trusted_nets, 'trusted networks')}</div></div>
      </div>
    </div>`;

  const risky = risks.length ? `
    <div class="bp-card risk"><div class="t">${risks.length} high-risk bypass${risks.length === 1 ? '' : 'es'}</div>
      <ul class="bp-risks">${risks.map(r => `<li>
        <span class="nm">${E(r.name)}</span>
        <span><span class="bp-chip src">${E(r.source)} #${E(String(r.id))}</span> <span class="bp-chip act">${E(r.action)}</span></span>
        <span class="why">${E(r.reason)}</span></li>`).join('')}</ul></div>` : '';

  const diag = (data.diagnostics || []).length ? `
    <div class="bp-card warn"><div class="t">${data.diagnostics.length} section${data.diagnostics.length === 1 ? '' : 's'} could not be read; the rest rendered below</div>
      <details><summary style="cursor:pointer;color:var(--accent);font-size:0.82rem;">Show details</summary>
      <ul style="margin:0.4rem 0 0 1.1rem;font-size:0.8rem;color:var(--dim);">${data.diagnostics.map(d => `<li><strong>${E(d.section)}</strong>: <code>${E(d.error_type || '?')}</code> ${E(d.error || '')}</li>`).join('')}</ul></details></div>` : '';

  const table = (items, cols, opts = {}) => {
    if (!items || !items.length) return '<div class="bp-none">Nothing here.</div>';
    const cls = c => (opts.mono || []).includes(c) ? ' class="mono"' : ((opts.num || []).includes(c) ? ' class="num"' : '');
    return `<div class="max"><table class="bp-table"><thead><tr>${cols.map(c => `<th>${E(c)}</th>`).join('')}</tr></thead><tbody>${items.map(it => `<tr>${cols.map(c => {
      let v = it[c]; if (Array.isArray(v)) v = v.slice(0, 5).join(', ') + (v.length > 5 ? ` +${v.length - 5}` : '');
      return `<td${cls(c)}>${E(String(v == null || v === '' ? '—' : v))}</td>`;
    }).join('')}</tr>`).join('')}</tbody></table></div>`;
  };
  const section = (label, count, body, extra = '') => {
    const n = count || 0;
    return `<details class="bp-sec ${n ? 'has-items' : 'empty'}" ${n ? 'open' : ''}><summary>${E(label)}${extra}<span class="ct">${n}</span></summary><div>${body}</div></details>`;
  };
  const secs = data.sections || {};
  const ruleCols = ['id', 'name', 'action', 'state', 'scope'];
  const ruleOpts = { mono: ['id'] };
  const ofTotal = sec => (sec.total_rules || sec.total_ssl_rules) ? `<span class="ct" style="margin-left:0.5rem;">of ${sec.total_rules || sec.total_ssl_rules}</span>` : '';
  let rulesHtml = '<div class="bp-h">Rules that skip inspection</div>';
  for (const [key, label] of [['ssl_bypass_rules', 'SSL inspection bypass rules'], ['url_filter_allow', 'URL Filtering allow rules'], ['firewall_allow', 'Firewall allow rules'], ['dlp_allow', 'DLP allow / bypass rules']]) {
    const sec = secs[key] || {};
    rulesHtml += section(label, sec.count, table(sec.items, ruleCols, ruleOpts), ofTotal(sec));
  }
  const exm = secs.ssl_exemptions || {};
  rulesHtml += section('SSL exemptions and Do-Not-Inspect categories', exm.count, table(exm.items, ['source', 'field', 'value'], { mono: ['value'] }));

  const zcc = secs.zcc || {};
  let zccHtml = '<div class="bp-h">Client Connector bypasses</div>';
  for (const [key, label, cols] of [['apps', 'App bypass', ['profile', 'name', 'path', 'os']], ['processes', 'Process bypass', ['profile', 'name']],
                                    ['ips', 'IP bypass', ['profile', 'value']], ['domains', 'Domain bypass', ['profile', 'value']], ['trusted_networks', 'Trusted networks', ['profile', 'value']]]) {
    const sec = zcc[key] || {};
    zccHtml += section(label, sec.count, table(sec.items, cols, { mono: ['value', 'path'] }));
  }
  if (zcc.endpoints_probed && zcc.endpoints_probed.length) {
    const rows = zcc.endpoints_probed.map(p => `<tr><td class="mono">${E(p.endpoint)}</td><td style="color:${p.status === 200 ? 'var(--pass)' : (p.status === 0 ? 'var(--fail)' : 'var(--warn)')};font-weight:600;">${p.status}</td><td class="dim">${p.item_count != null ? p.item_count + ' profile(s)' : (p.error ? E(p.error) : '—')}</td></tr>`).join('');
    zccHtml += `<details class="bp-sec empty"><summary>Client Connector endpoints probed<span class="ct">${zcc.endpoints_probed.length}</span></summary><div><table class="bp-table"><thead><tr><th>Endpoint</th><th>Status</th><th>Response</th></tr></thead><tbody>${rows}</tbody></table></div></details>`;
  }

  const agg = data.aggregated || {};
  const aggBlock = (title, key, valueLabel) => {
    const items = (agg[key] || {}).items || [];
    if (!items.length) return section(title, 0, '<div class="bp-none">Nothing here.</div>');
    const rows = items.map((it, i) => `<tr><td class="num">${i + 1}</td><td class="mono">${E(String(it.value || ''))}</td><td class="num">${it.count}</td><td>${(it.rules || []).map(r => `<span class="bp-ref" title="${E(r.name || '')}">${E(r.source || '')}#${r.id != null ? r.id : '?'}</span>`).join('')}</td></tr>`).join('');
    return section(title, items.length, `<div class="max"><table class="bp-table"><thead><tr><th>#</th><th>${E(valueLabel)}</th><th>Refs</th><th>Referenced by</th></tr></thead><tbody>${rows}</tbody></table></div>`);
  };
  const aggHtml = `
    <div class="bp-h">Effective bypass universe</div>
    <p style="color:var(--dim);font-size:0.82rem;margin:0 0 0.5rem;">Every URL, cloud application, category and IP exempted anywhere in the tenant, deduplicated and traced back to the rule that exempted it. URL categories are expanded into their URLs.</p>
    ${aggBlock('All URLs bypassed (explicit, inherited from categories, and Client Connector domains)', 'all_urls_bypassed', 'URL')}
    ${aggBlock('Bypassed URL categories', 'url_categories', 'URL category')}
    ${aggBlock('Explicitly listed URLs', 'urls', 'URL')}
    ${aggBlock('URLs inherited from categories', 'inherited_urls', 'URL (via category)')}
    ${aggBlock('Bypassed cloud applications', 'cloud_applications', 'Cloud app')}
    ${aggBlock('Bypassed cloud app categories', 'cloud_app_categories', 'Cloud app category')}
    ${aggBlock('Bypassed destination IPs', 'dest_ips', 'IP / CIDR')}
    ${aggBlock('Bypassed destination IP groups', 'dest_ip_groups', 'IP group')}
    ${aggBlock('Client Connector apps', 'zcc_apps', 'App')}
    ${aggBlock('Client Connector processes', 'zcc_processes', 'Process')}
    ${aggBlock('Client Connector IPs', 'zcc_ips', 'IP / CIDR')}
    ${aggBlock('Client Connector domains', 'zcc_domains', 'Domain')}
    ${aggBlock('Client Connector trusted networks', 'zcc_trusted_networks', 'Network')}`;

  let catHtml = '';
  const cats = agg.category_expansion || [];
  if (cats.length) {
    const rows = cats.map(c => {
      const urls = (c.urls || []).concat(c.db_urls || []);
      const chips = urls.slice(0, 50).map(u => `<span class="bp-code">${E(u)}</span>`).join(' ');
      const more = urls.length > 50 ? `<div class="bp-none">…and ${urls.length - 50} more (the export has the full list)</div>` : '';
      const note = c.note ? `<div style="color:var(--warn);font-size:0.8rem;margin-bottom:0.3rem;">${E(c.note)}</div>` : '';
      const rule = c.referenced_by_rule || {};
      return `<details class="bp-sec has-items"><summary>${E(c.category || '?')} <span class="bp-chip">${E(c.type || '?')}</span> <span class="bp-ref">${E(rule.source || '?')}#${rule.id != null ? rule.id : '?'} ${E(rule.name || '')}</span><span class="ct">${urls.length} URLs</span></summary><div>${note}${chips || '<div class="bp-none">No enumerable URLs.</div>'}${more}</div></details>`;
    }).join('');
    catHtml = `<div class="bp-h">What each URL category contributes</div>${rows}`;
  }

  const guidance = (data.guidance || []).length ? `<div class="bp-card info bp-guide" style="margin-top:1rem;"><div class="t">Guidance</div><ul>${data.guidance.map(g => `<li>${E(g)}</li>`).join('')}</ul></div>` : '';

  (container || document.getElementById('bypassResult')).innerHTML = top + diag + risky + rulesHtml + zccHtml + aggHtml + catHtml + guidance;
};


