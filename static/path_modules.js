// ── Path modules: one renderer for every policy module on a traced path ──
// The Path analyzer's steps, in the order they apply, all in one shape and
// drawn by this one file: ZPA (application segment, bypass, client
// forwarding, access policy), the Cloud or Branch Connector for a
// workload, the PAC file (evaluated, never run) and every ZIA module. Each
// hop renders as its name, a verdict chip, the deciding rule with its
// order, the other rules that also match (compressed), the earlier rules
// that could decide instead, and each criterion of the deciding rule as
// match, no match or unknown. It uses the page's own classes (df-hop,
// df-chip, df-table, df-hint) and colour tokens only.
//
// The data shape of one hop (zia_path_modules.module_hop on the server):
//   {
//     module:   'Cloud Firewall',                 // the module's name, shown as is
//     verdict:  'block',                          // allow | block | caution | isolate | redirect | inspect |
//                                                 // decrypt | no_decrypt | none | blind | skipped | conditional |
//                                                 // unknown | not_applicable | not_reached | out_of_scope |
//                                                 // and before ZIA: matched | not_matched | intercepted |
//                                                 // bypassed | forwarded | dropped | carried
//     rule:     { name: 'Block QUIC', order: 1 }, // the deciding rule, or null (optional: action, default)
//     overlaps: [{ name, order, action, differs, detail }],// other rules that also match; differs: another outcome
//     criteria: [{ name, state, detail }],        // the deciding rule's criteria;
//                                                 // state: 'match' | 'no_match' | 'unknown'
//     notes:    ['...'],                          // plain sentences
//   }
// Optional fields: key, detail (one sentence under the name), certainty
// ('definite' | 'conditional' | 'unknown'), overlaps_catch_all (how many
// catch-all or default rules also match), could_override ([{ name, order,
// action, criteria, detail }]: earlier rules with an unknown criterion and
// another outcome), modifier (true: it changes what later modules see, like
// SSL inspection), position (its place in the order).
//
// API: PathModules.render(hops) -> HTML (an ordered list);
//      PathModules.hop(hop) -> HTML for one hop;
//      PathModules.section(res) -> the Path analyzer result's module
//        sections: the steps before ZIA (res.modules), then the ZIA modules
//        (res.zia_modules), each in order;
//      PathModules.portHint(protocol, port) -> the name of a well-known port.
(function (root) {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const VERDICT = {
    allow: ['Allow', 'ok'], block: ['Block', 'block'], caution: ['Caution', 'warn'], isolate: ['Isolate', 'warn'],
    redirect: ['Redirect', 'warn'], inspect: ['Inspect', 'ok'], decrypt: ['Decrypt', 'ok'], no_decrypt: ['Do not decrypt', 'fail'],
    none: ['No rule', 'dim'], blind: ['Blind', 'fail'], skipped: ['Skipped', 'dim'], conditional: ['Conditional', 'warn'],
    unknown: ['Unknown', 'dim'], not_applicable: ['Not applicable', 'dim'], not_reached: ['Not reached', 'dim'],
    out_of_scope: ['Not in scope', 'dim'],
    // the steps before ZIA (ZPA, the connector, the PAC file)
    matched: ['Matches', 'ok'], not_matched: ['No match', 'dim'], intercepted: ['Intercepted', 'ok'], bypassed: ['Bypasses', 'warn'],
    forwarded: ['Forwarded', 'ok'], dropped: ['Dropped', 'block'], carried: ['Carried', 'ok'],
  };
  const STATE = { match: ['Match', 'ok'], no_match: ['No match', 'dim'], unknown: ['Unknown', 'warn'] };

  function chip(table, key) {
    const [lab, cls] = table[key] || [String(key || '').replace(/_/g, ' '), 'dim'];
    return `<span class="df-chip st-${E(cls)}">${E(lab)}</span>`;
  }
  function ruleText(r) {
    if (!r || !r.name) return '';
    const where = r.default ? 'default rule' : (r.order != null && r.order !== '' ? `order ${r.order}` : '');
    return `<code>${E(r.name)}</code>${where ? ` <span class="df-by">(${E(where)})</span>` : ''}${r.action ? ` <span class="df-by">${E(r.action)}</span>` : ''}`;
  }
  function criteriaTable(list, caption) {
    return `<div class="df-tablewrap"><table class="df-table pm-crit"><caption class="sr-only">${E(caption)}</caption>
      <thead><tr><th scope="col">Criterion</th><th scope="col">Result</th><th scope="col">Why</th></tr></thead>
      <tbody>${list.map(c => `<tr><td>${E(c.name)}</td><td>${chip(STATE, c.state)}</td><td class="df-hop-d">${E(c.detail || '')}</td></tr>`).join('')}</tbody></table></div>`;
  }
  function ruleRows(list) {
    return `<div class="df-tablewrap"><table class="df-table"><caption class="sr-only">Rules</caption>
      <thead><tr><th scope="col">Rule</th><th scope="col">Order</th><th scope="col">Action</th><th scope="col">Outcome</th></tr></thead>
      <tbody>${list.map(o => `<tr><td><code>${E(o.name)}</code>${o.detail ? `<div class="df-hop-d">${E(o.detail)}</div>` : ''}</td><td>${E(o.order == null ? '' : o.order)}</td><td>${E(o.action || '')}</td><td>${o.differs ? 'different' : 'same'}</td></tr>`).join('')}</tbody></table></div>`;
  }
  // Overlaps, compressed to one line; the rules themselves on demand.
  function overlapsHtml(h) {
    const list = h.overlaps || [], extra = Number(h.overlaps_catch_all) || 0;
    if (!list.length && !extra) return '';
    const differ = list.filter(o => o.differs).length;
    const bits = [];
    if (list.length) bits.push(`${list.length} rule${list.length === 1 ? '' : 's'}${differ ? ` (${differ} with another outcome)` : ''}`);
    if (extra) bits.push(`${extra} catch-all or default rule${extra === 1 ? '' : 's'}`);
    const line = `<strong>Also matched:</strong> ${E(bits.join(' and '))}. They never apply here: ${h.key === 'zpa_segment' ? 'the most specific match decides' : 'the first match decides'}.`;
    return list.length ? `<details class="pm-more"><summary class="df-hop-d">${line}</summary>${ruleRows(list)}</details>` : `<div class="df-hop-d">${line}</div>`;
  }
  function couldHtml(h) {
    const list = h.could_override || [];
    if (!list.length) return '';
    return `<details class="pm-more"><summary class="df-hop-d"><strong>Could apply first:</strong> ${E(list.length)} rule${list.length === 1 ? '' : 's'} whose conditions are not all known, with another outcome.</summary>
      ${list.map(o => `<div class="pm-could"><div class="df-hop-d">${ruleText(o)}</div>${o.detail ? `<div class="df-hop-d">${E(o.detail)}</div>` : ''}${(o.criteria || []).length ? criteriaTable(o.criteria, `Criteria of ${o.name}`) : ''}</div>`).join('')}</details>`;
  }
  function hop(h) {
    const [, cls] = VERDICT[h.verdict] || ['', 'dim'];
    const crit = h.criteria || [];
    const showRule = h.rule && h.rule.name;
    return `<li class="df-hop st-${E(cls)} pm-hop" data-module="${E(h.key || h.module)}">
      <div class="df-hop-h">${h.position != null ? `<span class="df-by">${E(h.position)}.</span>` : ''}<strong>${E(h.module)}</strong>${chip(VERDICT, h.verdict)}${h.modifier ? '<span class="df-by">modifier</span>' : ''}${h.certainty === 'conditional' && h.verdict !== 'conditional' ? chip(VERDICT, 'conditional') : ''}</div>
      ${h.detail ? `<div class="df-hop-d">${E(h.detail)}</div>` : ''}
      ${showRule ? `<div class="df-hop-d pm-rule"><strong>Deciding rule:</strong> ${ruleText(h.rule)}</div>` : ''}
      ${showRule ? (crit.length ? criteriaTable(crit, `Criteria of ${h.rule.name}`) : '<div class="df-hop-d">No conditions: this rule matches all traffic that reaches it.</div>') : ''}
      ${overlapsHtml(h)}${couldHtml(h)}
      ${(h.notes || []).map(n => `<div class="df-hop-d pm-note">${E(n)}</div>`).join('')}
    </li>`;
  }
  function render(hops) {
    const list = (hops || []).filter(Boolean);
    if (!list.length) return '<div class="df-hop-d">No module was evaluated for this path.</div>';
    return `<ol class="pm-list">${list.map(hop).join('')}</ol>`;
  }

  // ── The Path analyzer's parts ─────────────────────────────────────
  // The well-known ports the page names as they are typed. The server
  // (zia_path_modules.WELL_KNOWN) is what decides; this is the hint only.
  const PORT_HINT = {
    'tcp/80': 'HTTP (web)', 'tcp/443': 'HTTPS (web)', 'udp/443': 'QUIC (HTTP/3 over UDP): never seen by the web proxy',
    'tcp/8080': 'HTTP on 8080', 'tcp/8443': 'HTTPS on 8443', 'tcp/53': 'DNS', 'udp/53': 'DNS', 'tcp/853': 'DNS over TLS',
    'tcp/22': 'SSH', 'tcp/23': 'Telnet', 'tcp/21': 'FTP', 'tcp/25': 'SMTP (mail)', 'tcp/587': 'SMTP (mail)', 'tcp/465': 'SMTP over TLS',
    'tcp/110': 'POP3', 'tcp/995': 'POP3 over TLS', 'tcp/143': 'IMAP', 'tcp/993': 'IMAP over TLS', 'udp/123': 'NTP (time)',
    'tcp/389': 'LDAP', 'tcp/636': 'LDAP over TLS', 'tcp/445': 'SMB (file sharing)', 'tcp/3389': 'Remote Desktop (RDP)',
    'udp/3389': 'Remote Desktop (RDP)', 'tcp/5900': 'VNC', 'udp/500': 'IPsec IKE', 'udp/4500': 'IPsec IKE', 'udp/1194': 'OpenVPN',
    'udp/51820': 'WireGuard', 'tcp/1723': 'PPTP VPN', 'udp/3478': 'STUN (calls and meetings)', 'tcp/1433': 'Microsoft SQL Server',
    'tcp/3306': 'MySQL', 'tcp/5432': 'PostgreSQL',
  };
  // One sentence for the protocol and port chosen ('' when nothing is).
  function portHint(protocol, port) {
    const proto = protocol || 'tcp', p = String(port == null ? '' : port).trim();
    if (!p) return protocol ? `${proto.toUpperCase()}, port from the URL (else 443).` : '';
    const name = PORT_HINT[`${proto}/${p}`];
    return `${proto.toUpperCase()}/${p}${name ? ` is ${name}` : ''}.`;
  }
  // The steps before ZIA: ZPA, the connector for a workload, the PAC file.
  function beforeSection(res) {
    const list = (res && res.modules) || [];
    if (!list.length) return '';
    const has = test => list.some(m => test(String(m.key || '')));
    const parts = [has(k => k === 'zpa' || k.startsWith('zpa_')) && 'ZPA', has(k => k === 'workload_groups' || k === 'connector_forwarding') && 'the connector',
      has(k => k === 'pac') && 'the PAC file'].filter(Boolean);
    const said = parts.length > 1 ? `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}` : (parts[0] || 'the steps in front');
    return `<section class="pm-section" aria-labelledby="pmBeforeH">
      <h2 class="df-h" id="pmBeforeH">Before ZIA: ${E(said)}</h2>
      <p class="df-hint">What decides the traffic before ZIA, in the order it is applied.${parts.includes('ZPA') ? ' ZPA comes first: a destination ZPA carries never reaches ZIA.' : ''}${parts.includes('the PAC file') ? ' The PAC file is evaluated, never run.' : ''} A criterion marked Unknown depends on something you did not give, or on a condition this page cannot evaluate.</p>
      ${render(list)}
    </section>`;
  }
  // Where the traffic ends: the module that blocks for certain, else a
  // block that depends on unknown conditions, else the verdict's stop.
  function endsAt(z, v) {
    const mods = z.modules || [];
    const stop = mods.find(m => m.key === z.stops_at);
    if (stop) return stop.module;
    if (v.stops_at) return v.stops_at;
    const maybe = mods.find(m => m.verdict === 'block' && m.certainty === 'conditional');
    return maybe ? `${maybe.module}, if its conditions hold` : 'reaches the destination';
  }
  const CERTAINTY = { definite: ['Definite', 'ok'], conditional: ['Conditional', 'warn'] };
  function ziaSection(res) {
    const z = res && res.zia_modules;
    if (!z || !Array.isArray(z.modules)) return '';
    const v = res.verdict || {};
    const reasons = z.reasons || [];
    return `<section class="pm-section" aria-labelledby="pmZiaH">
      <h2 class="df-h" id="pmZiaH">ZIA modules, in the order the cloud applies them</h2>
      <p class="df-hint">Each module shows the rule that decides, the rules that also match later, and every condition of the deciding rule as match, no match or unknown. A condition this tool cannot check is unknown, never guessed.</p>
      <div class="pa-facts">
        <span class="df-prof"><span class="k">Traffic</span><span class="v">${E((z.traffic || {}).label || '')}</span></span>
        <span class="df-prof"><span class="k">Result</span><span class="v">${chip(CERTAINTY, v.certainty || z.certainty)}</span></span>
        <span class="df-prof"><span class="k">Ends at</span><span class="v">${E(endsAt(z, v))}</span></span>
      </div>
      ${reasons.length ? `<details class="pm-more" open><summary class="df-hop-d"><strong>Conditional because:</strong> ${E(reasons.length)} thing${reasons.length === 1 ? '' : 's'} this result depends on.</summary><ul class="pa-assume">${reasons.map(r => `<li>${E(r)}</li>`).join('')}</ul></details>` : '<p class="df-hint">Definite: every module that decides here has all its conditions known.</p>'}
      ${z.modifier ? `<ol class="pm-list pm-modifier">${hop(z.modifier)}</ol>` : ''}
      ${render(z.modules)}
    </section>`;
  }
  // Every module section of a result, in the order the traffic meets them.
  function section(res) { return beforeSection(res) + ziaSection(res); }

  root.PathModules = { render, hop, section, portHint, VERDICT, STATE };
})(window);
