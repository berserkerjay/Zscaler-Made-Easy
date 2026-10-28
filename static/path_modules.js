// ── Path modules: one renderer for every policy module on a traced path ──
// Shared by every Path analyzer view that shows a module's decision (ZIA
// modules, ZPA, workloads, what-if, test a list). Each hop renders as its
// name, a verdict chip, the deciding rule with its order, the later rules
// that also match (compressed), and each criterion of the deciding rule as
// match, no match or unknown. It uses the page's own classes (df-hop,
// df-chip, df-table, df-hint) and colour tokens only.
//
// The data shape of one hop:
//   {
//     module:   'Cloud Firewall',                 // the module's name, shown as is
//     verdict:  'block',                          // allow | block | caution | isolate | redirect | inspect |
//                                                 // decrypt | no_decrypt | none | blind | skipped | conditional |
//                                                 // unknown | not_applicable | not_reached | out_of_scope
//     rule:     { name: 'Block QUIC', order: 1 }, // the deciding rule, or null (optional: action, default)
//     overlaps: [{ name, order, action, differs }],// later rules that also match; differs: another outcome
//     criteria: [{ name, state, detail }],        // the deciding rule's criteria;
//                                                 // state: 'match' | 'no_match' | 'unknown'
//     notes:    ['...'],                          // plain sentences
//   }
// Optional fields: key, detail (one sentence under the name), certainty
// ('definite' | 'conditional' | 'unknown'), overlaps_catch_all (how many
// catch-all or default rules also match), could_override ([{ name, order,
// action, criteria }]: earlier rules with an unknown criterion and another
// outcome), modifier (true: it changes what later modules see, like SSL
// inspection), position (its place in the order).
//
// API: PathModules.render(hops) -> HTML (an ordered list);
//      PathModules.hop(hop) -> HTML for one hop.
// PathModules.zia holds the Path analyzer's ZIA-module parts: the protocol
// and port inputs and the result section.
(function (root) {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const VERDICT = {
    allow: ['Allow', 'ok'], block: ['Block', 'block'], caution: ['Caution', 'warn'], isolate: ['Isolate', 'warn'],
    redirect: ['Redirect', 'warn'], inspect: ['Inspect', 'ok'], decrypt: ['Decrypt', 'ok'], no_decrypt: ['Do not decrypt', 'fail'],
    none: ['No rule', 'dim'], blind: ['Blind', 'fail'], skipped: ['Skipped', 'dim'], conditional: ['Conditional', 'warn'],
    unknown: ['Unknown', 'dim'], not_applicable: ['Not applicable', 'dim'], not_reached: ['Not reached', 'dim'],
    out_of_scope: ['Not in scope', 'dim'],
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
      <tbody>${list.map(o => `<tr><td><code>${E(o.name)}</code></td><td>${E(o.order == null ? '' : o.order)}</td><td>${E(o.action || '')}</td><td>${o.differs ? 'different' : 'same'}</td></tr>`).join('')}</tbody></table></div>`;
  }
  // Overlaps, compressed to one line; the rules themselves on demand.
  function overlapsHtml(h) {
    const list = h.overlaps || [], extra = Number(h.overlaps_catch_all) || 0;
    if (!list.length && !extra) return '';
    const differ = list.filter(o => o.differs).length;
    const bits = [];
    if (list.length) bits.push(`${list.length} rule${list.length === 1 ? '' : 's'}${differ ? ` (${differ} with another outcome)` : ''}`);
    if (extra) bits.push(`${extra} catch-all or default rule${extra === 1 ? '' : 's'}`);
    const line = `<strong>Also matched later:</strong> ${E(bits.join(' and '))}. They never apply here: the first match decides.`;
    return list.length ? `<details class="pm-more"><summary class="df-hop-d">${line}</summary>${ruleRows(list)}</details>` : `<div class="df-hop-d">${line}</div>`;
  }
  function couldHtml(h) {
    const list = h.could_override || [];
    if (!list.length) return '';
    return `<details class="pm-more"><summary class="df-hop-d"><strong>Could apply first:</strong> ${E(list.length)} rule${list.length === 1 ? '' : 's'} whose conditions are not all known, with another outcome.</summary>
      ${list.map(o => `<div class="pm-could"><div class="df-hop-d">${ruleText(o)}</div>${(o.criteria || []).length ? criteriaTable(o.criteria, `Criteria of ${o.name}`) : ''}</div>`).join('')}</details>`;
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

  // ── The Path analyzer's ZIA modules ───────────────────────────────
  // The well-known ports the inputs explain as they are typed. The server
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
  function hint() {
    const p = document.getElementById('paProto'), n = document.getElementById('paPort'), out = document.getElementById('paPortHint');
    if (!p || !n || !out) return;
    const proto = p.value || 'tcp', port = String(n.value || '').trim();
    if (!port) { out.textContent = p.value ? `${proto.toUpperCase()}, port from the URL (else 443).` : ''; return; }
    const name = PORT_HINT[`${proto}/${port}`];
    out.textContent = `${proto.toUpperCase()}/${port}${name ? ` is ${name}` : ''}.`;
  }
  // The protocol and port inputs, placed after `after` (the platform control).
  function mountControls(after) {
    if (!after || document.getElementById('paProto')) return;
    after.insertAdjacentHTML('afterend', `<label class="df-ctl"><span class="lbl">Protocol</span><select id="paProto" aria-label="Protocol of the traffic" aria-describedby="paPortHint">
        <option value="">From the URL</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
      <label class="df-ctl pm-port"><span class="lbl">Port</span><input type="number" id="paPort" min="1" max="65535" step="1" inputmode="numeric" placeholder="443" aria-label="Destination port (1 to 65535)" aria-describedby="paPortHint"></label>
      <span class="df-hint pm-port-hint" id="paPortHint" aria-live="polite"></span>`);
    document.getElementById('paProto').addEventListener('change', hint);
    document.getElementById('paPort').addEventListener('input', hint);
  }
  // What the request adds: {protocol, port}, only what the operator chose.
  function input() {
    const p = document.getElementById('paProto'), n = document.getElementById('paPort');
    const out = {};
    if (p && p.value) out.protocol = p.value;
    if (n && String(n.value).trim() !== '') out.port = Number(n.value);
    return out;
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
  function section(res) {
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
  // Put the section right after the verdict of a rendered result.
  function mount(container, res) {
    if (!container) return;
    const old = container.querySelector('.pm-section'); if (old) old.remove();
    const html = section(res);
    if (!html) return;
    const verdict = container.querySelector('.pa-verdict');
    if (verdict) verdict.insertAdjacentHTML('afterend', html); else container.insertAdjacentHTML('afterbegin', html);
  }

  root.PathModules = { render, hop, VERDICT, STATE, zia: { mountControls, input, section, mount } };
})(window);
