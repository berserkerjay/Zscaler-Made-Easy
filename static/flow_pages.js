// ── Live motion on the ZPA, Traffic insights, Live DLP feed and Bypass pages ──
// One model per page, all drawn with the Flow animator's engine
// (static/flow_anim.js: FA.animator, FA.newSvg, FA.box, FA.curve,
// FA.hopPlayer, FA.live); no other animation code, no external script.
//   - ZPA infrastructure (zpaInfraModel): users and IdPs → the ZPA cloud →
//     App Connector groups → app segments, from the map the ZPA overview
//     already drew. Packets run on healthy links; a link to a connector
//     group whose App Connectors are down stops (red, dashed, packets end
//     half way); one with a connector down or on an outdated version
//     flickers red while packets still pass.
//   - ZPA diagnosis (zpaDiagModel): one packet walks app segment → segment
//     group → each access rule in order (each one that does not match says
//     why) → the rule that decides lights up → server groups → App
//     Connectors → the destination, on FA.hopPlayer.
//   - Traffic insights (insightsFlowModel): a Sankey-style flow from the
//     Z-Insights numbers on the page: locations → web traffic → actions,
//     firewall traffic → actions, or cloud applications → sanctioned state.
//     Stream widths come from those numbers and nothing else.
//   - Live DLP feed (FA.liveModel + FA.live): each incident as it lands,
//     channel → dictionaries → engine → rule → configured action → incident
//     receiver; liveLine says the same in words, with no user or file name.
//   - Bypass report (bypassFlowModel): the traffic path with a stream
//     peeling off at each point that skips the Zero Trust Exchange or its
//     inspection (Client Connector bypass, ZPA bypass, PAC DIRECT, SSL Do
//     Not Inspect) and the allow rules; widths are the report's own counts.
// Models are pure (the tests run them under node). Rendering honours
// prefers-reduced-motion (a still picture and a Play button), pauses while
// the tab is hidden (FA.animator), and every picture has a text
// alternative. Tenant strings only ever reach the page as text nodes.
(function (root) {
  'use strict';
  const num = v => { const n = Number(v); return v == null || v === '' || !Number.isFinite(n) ? null : n; };
  const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + 's')}`;
  const clipT = (s, n) => { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
  const fmt = n => (n == null ? '—' : Number(n).toLocaleString('en-US'));
  function bytes(n) {
    if (n == null) return '—';
    const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']; let v = Number(n), i = 0;
    while (Math.abs(v) >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return `${i ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
  }

  // ── ZPA: infrastructure ─────────────────────────────────────────
  // graph: overview.graph from zpa_overview.py ({columns, nodes, edges}).
  const ZPA_DOWN_FLAGS = ['all_down', 'no_connectors'];
  function connectorHealth(n) {
    if (!n) return 'unknown';
    const f = n.flags || [];
    if (n.status === 'off') return 'off';
    if (n.aggregate) return n.status === 'fail' ? 'some_down' : n.status === 'warn' ? 'some_outdated' : n.status === 'unknown' ? 'unknown' : 'ok';
    if (f.indexOf('not_connected') >= 0 || n.status === 'fail') return 'down';
    if (f.indexOf('outdated') >= 0) return 'outdated';
    if (f.indexOf('status_unknown') >= 0 || n.status === 'unknown') return 'unknown';
    return 'ok';
  }
  const STATE_TONE = { live: 'pass', flicker: 'warn', stop: 'stop', unknown: 'idle', idle: 'idle' };
  function zpaInfraModel(graph) {
    if (!graph || !Array.isArray(graph.nodes)) return null;
    const nodes = graph.nodes, edges = graph.edges || [];
    const by = {}; nodes.forEach(n => { by[n.id] = n; });
    const col = k => nodes.filter(n => n.col === k);
    const out = {}, inn = {};
    edges.forEach(([a, b]) => { (out[a] = out[a] || []).push(b); (inn[b] = inn[b] || []).push(a); });
    const kids = (id, c) => (out[id] || []).filter(x => by[x] && by[x].col === c);

    // Each connector group: its App Connectors and what that makes of its link.
    const groups = col('connector_groups').map(g => {
      const cons = kids(g.id, 'connectors').map(id => by[id]);
      const h = { total: 0, down: 0, outdated: 0, unknown: 0, some: false };
      cons.forEach(c => {
        const s = connectorHealth(c);
        if (s === 'off') return;
        if (c.aggregate) { h.total += Number(c.count) || 0; if (s === 'some_down' || s === 'some_outdated') h.some = true; if (s === 'unknown') h.unknown += Number(c.count) || 0; return; }
        h.total++;
        if (s === 'down') h.down++; else if (s === 'outdated') h.outdated++; else if (s === 'unknown') h.unknown++;
      });
      const f = g.flags || [];
      let state = 'live', reason = 'connected';
      const names = s => cons.filter(c => !c.aggregate && connectorHealth(c) === s).map(c => c.label);
      if (g.status === 'off') { state = 'stop'; reason = 'the group is disabled'; }
      else if (f.indexOf('no_connectors') >= 0 || (!h.total && g.sub === 'no connectors')) { state = 'stop'; reason = 'no App Connector in this group'; }
      else if (f.indexOf('all_down') >= 0 || (h.total && h.down === h.total)) { state = 'stop'; reason = `every App Connector is down${h.down ? ` (${names('down').join(', ')})` : ''}`; }
      else if (h.down || h.some) { state = 'flicker'; reason = h.down ? `${plural(h.down, 'App Connector')} down: ${names('down').join(', ')}` : 'some App Connectors in a grouped box need attention'; }
      else if (h.outdated || f.indexOf('versions') >= 0) { state = 'flicker'; reason = h.outdated ? `${plural(h.outdated, 'App Connector')} not on the expected version: ${names('outdated').join(', ')}` : 'mixed or outdated App Connector versions'; }
      else if (g.status === 'unknown' || (!h.total && !cons.length)) { state = 'unknown'; reason = cons.length ? 'status not read' : 'no App Connector listed for it'; }
      else if (h.unknown && h.unknown === h.total) { state = 'unknown'; reason = 'its App Connectors report no status'; }
      return { id: g.id, label: g.label, sub: g.sub, aggregate: !!g.aggregate, state, reason, connectors: h };
    });
    const gState = {}; groups.forEach(g => { gState[g.id] = g; });

    // Which app segments each connector group serves: segment → server group → connector group.
    const serves = {};
    edges.forEach(([s, sg]) => {
      if (!by[s] || !by[sg] || by[s].col !== 'segments' || by[sg].col !== 'server_groups') return;
      kids(sg, 'connector_groups').forEach(g => { (serves[g] = serves[g] || []); if (serves[g].indexOf(s) < 0) serves[g].push(s); });
    });

    const users = col('idps'), apps = col('segments');
    const links = [];
    users.forEach(u => {
      const reach = (out[u.id] || []).length > 0;
      const state = u.status === 'off' ? 'stop' : u.status === 'unknown' ? 'unknown' : reach ? 'live' : 'idle';
      links.push({ from: u.id, to: 'zpa:cloud', state, reason: u.status === 'off' ? 'IdP disabled' : reach ? 'signs users in' : 'reaches no access rule' });
    });
    groups.forEach(g => links.push({ from: 'zpa:cloud', to: g.id, state: g.state, reason: g.reason }));
    groups.forEach(g => (serves[g.id] || []).forEach(s => {
      const a = by[s];
      let state = g.state, reason = g.reason;
      if (state === 'live' && a.status === 'off') { state = 'stop'; reason = 'app segment disabled'; }
      else if (state === 'live' && a.status === 'unknown') { state = 'unknown'; reason = 'app segment not read'; }
      links.push({ from: g.id, to: s, state, reason });
    }));
    const tally = { live: 0, flicker: 0, stop: 0, unknown: 0, idle: 0 };
    links.forEach(l => { tally[l.state]++; });
    const cnt = groups.reduce((a, g) => ({ down: a.down + g.connectors.down, outdated: a.outdated + g.connectors.outdated }), { down: 0, outdated: 0 });
    const userTone = u => (u.status === 'off' ? 'after' : u.status === 'unknown' ? 'idle' : u.status === 'fail' ? 'stop' : u.status === 'warn' ? 'warn' : 'pass');
    const appTone = a => (a.status === 'off' ? 'after' : a.status === 'fail' ? 'stop' : a.status === 'warn' ? 'warn' : a.status === 'unknown' ? 'idle' : 'pass');
    const cols = [
      { key: 'users', label: 'Users and IdPs', nodes: users.map(u => ({ id: u.id, label: u.label, sub: u.sub, tone: userTone(u) })) },
      { key: 'cloud', label: 'ZPA cloud', nodes: [{ id: 'zpa:cloud', label: 'ZPA cloud', sub: 'brokers each connection', tone: 'on' }] },
      { key: 'groups', label: 'App Connector groups', nodes: groups.map(g => ({ id: g.id, label: g.label, sub: g.sub, tone: STATE_TONE[g.state] })) },
      { key: 'apps', label: 'App segments', nodes: apps.map(a => ({ id: a.id, label: a.label, sub: a.sub, tone: appTone(a) })) },
    ];
    const summary = [
      `${plural(users.length, 'user source')} (IdPs, and "any signed-in user" for rules with no identity condition) sign in through the ZPA cloud, which hands each connection to an App Connector group; the group's App Connectors reach the app segments its server groups serve.`,
      `${plural(groups.length, 'App Connector group box', 'App Connector group boxes')}: ${groups.filter(g => g.state === 'live').length} carrying traffic, ${groups.filter(g => g.state === 'flicker').length} with a connector down or outdated (flickering), ${groups.filter(g => g.state === 'stop').length} stopped, ${groups.filter(g => g.state === 'unknown').length} not known.`,
    ];
    groups.filter(g => g.state !== 'live').forEach(g => summary.push(`${g.label}: ${g.state === 'stop' ? 'stopped' : g.state === 'flicker' ? 'flickering' : 'not known'}, ${g.reason}.`));
    const lonely = apps.filter(a => !links.some(l => l.to === a.id));
    if (lonely.length) summary.push(`${plural(lonely.length, 'app segment box', 'app segment boxes')} with no App Connector group drawn to it: ${lonely.slice(0, 5).map(a => a.label).join(', ')}${lonely.length > 5 ? ` and ${lonely.length - 5} more` : ''}.`);
    if (graph.aggregated) summary.push('Large columns end in a grouped "more" box, exactly as on the map below.');
    return { cols, links, groups, tally, connectors: cnt, summary };
  }

  // ── ZPA: one diagnosis, walked ──────────────────────────────────
  const RULE_WORD = { matched: 'decides', not_matched: 'no match', conditional: 'depends on the user', disabled: 'disabled' };
  const RULES_MAX = 12;
  function hopTone(status) { return status === 'ok' || status === 'info' ? 'pass' : status === 'blocked' || status === 'none' ? 'stop' : status === 'warn' ? 'warn' : 'idle'; }
  function zpaDiagModel(d) {
    if (!d || !d.verdict) return null;
    const hops = [], hop = k => (d.hops || []).find(h => h.key === k) || null;
    const v = d.verdict, dst = d.destination || {};
    const u = hop('user');
    hops.push({ key: 'user', label: 'User and device', sub: 'as you gave them', tone: 'pass', status: 'pass', note: u ? u.detail : '' });
    const seg = hop('segment');
    if (seg) {
      let tone = hopTone(seg.status);
      if (v.outcome === 'bypassed') tone = 'stop';
      hops.push({ key: 'segment', label: 'App segment', sub: seg.object || (seg.status === 'none' ? 'none matches' : ''), tone, status: seg.status, note: seg.detail });
    }
    const sg = hop('segment_group');
    if (sg) hops.push({ key: 'segment_group', label: 'Segment group', sub: sg.object || '', tone: hopTone(sg.status), status: sg.status, note: sg.detail });
    const acc = d.access, rules = [];
    let hidden = 0;
    if (acc && Array.isArray(acc.evaluated)) {
      const walked = acc.evaluated;
      let list = walked;
      if (walked.length > RULES_MAX) {
        const decider = walked.filter(w => w.status === 'matched');
        list = walked.slice(0, RULES_MAX - decider.length).concat(decider.filter(x => walked.indexOf(x) >= RULES_MAX - decider.length));
        hidden = walked.length - list.length;
      }
      list.forEach((w, i) => {
        const deny = String(w.action || '').toUpperCase() === 'DENY';
        const tone = w.status === 'matched' ? (deny ? 'stop' : 'pass') : w.status === 'conditional' ? 'warn' : 'idle';
        const r = { key: 'rule', order: w.order, name: w.name, action: w.action, status: w.status, why: w.why || '', decides: w.status === 'matched' };
        rules.push(r);
        hops.push({ key: 'rule', label: `${w.order != null ? `Rule ${w.order}: ` : ''}${w.name}`, sub: w.status === 'matched' ? `decides: ${w.action}` : RULE_WORD[w.status] || w.status, tone, status: w.status, decides: r.decides,
          note: `${RULE_WORD[w.status] || w.status}${w.why ? `: ${w.why}` : ''}` });
        if (hidden && i === list.length - 2 && list[list.length - 1].status === 'matched') {
          hops.push({ key: 'more', label: `${hidden} more rules`, sub: 'no match', tone: 'idle', status: 'not_matched', note: `${hidden} more rules were evaluated before the deciding one and did not match; the table lists them.` });
        }
      });
      if (!walked.some(w => w.status === 'matched')) {
        if (acc.decision === 'default_deny') hops.push({ key: 'default', label: 'Default deny', sub: 'no rule matches', tone: 'stop', status: 'blocked', decides: true, note: 'No access rule matches, so ZPA denies access by default.' });
        else hops.push({ key: 'default', label: 'No certain match', sub: 'depends on the user', tone: 'warn', status: 'warn', note: 'No rule matches for certain with what you gave; a rule that depends on the user would decide.' });
      }
    } else if (seg && seg.status !== 'none' && v.outcome !== 'bypassed') {
      const a = hop('access');
      hops.push({ key: 'access', label: 'Access policy', sub: 'could not be read', tone: 'warn', status: 'unknown', note: a ? a.detail : 'The access policy could not be read.' });
    }
    const serving = d.serving || {};
    const sgs = hop('server_groups');
    if (sgs) hops.push({ key: 'server_groups', label: 'Server groups', sub: (serving.server_groups || []).map(g => g.name).join(', ') || sgs.status, tone: hopTone(sgs.status), status: sgs.status, note: sgs.detail });
    const cg = hop('connectors');
    if (cg) {
      const gs = serving.connector_groups || [];
      const up = gs.reduce((a, g) => a + (Number(g.connected) || 0), 0), all = gs.reduce((a, g) => a + (Number(g.connectors) || 0), 0);
      hops.push({ key: 'connectors', label: 'App Connectors', sub: gs.length ? `${up} of ${all} connected` : 'none serve it', tone: hopTone(cg.status), status: cg.status, note: cg.detail });
    }
    const host = `${dst.host || ''}${dst.port ? ':' + dst.port : ''}`;
    hops.push({ key: 'dest', label: 'Destination', sub: host, tone: v.outcome === 'allowed' ? 'pass' : 'warn', status: 'dest', note: v.outcome === 'allowed' ? 'Reached through ZPA.' : 'Not reached as allowed traffic.' });
    let stop = -1;
    for (let i = 0; i < hops.length; i++) if (hops[i].tone === 'stop') { stop = i; break; }
    if (stop >= 0) for (let i = stop + 1; i < hops.length; i++) hops[i].tone = 'after';
    const OUT_TONE = { allowed: 'ok', denied: 'bad', unreachable: 'bad', bypassed: 'warn', not_zpa: 'warn', conditional: 'warn', unknown: 'warn' };
    return { hops, stop, rules, hidden, dest: host, verdict: { tone: OUT_TONE[v.outcome] || 'warn', outcome: v.outcome, text: v.headline || '' } };
  }

  // ── Traffic insights: Sankey-style flows ────────────────────────
  const SANKEY_MAX = 6;
  function actionTone(s) { s = String(s || '').toUpperCase(); return /ALLOW/.test(s) ? 'pass' : /BLOCK|DROP|DENY|RESET/.test(s) ? 'stop' : 'warn'; }
  function sanctionTone(s) { s = String(s || '').toLowerCase(); return /^unsanction/.test(s) ? 'stop' : /^sanction/.test(s) ? 'pass' : 'warn'; }
  // Rows → at most SANKEY_MAX nodes, the rest summed into one "N other" node.
  function fold(rows, key, valKey, otherWord, idPrefix) {
    const r = rows.map(x => ({ label: String(x[key] == null ? '' : x[key]) || '(unnamed)', value: num(x[valKey]) })).filter(x => x.value != null && x.value > 0);
    r.sort((a, b) => b.value - a.value);
    const keep = r.slice(0, SANKEY_MAX), rest = r.slice(SANKEY_MAX);
    const out = keep.map((x, i) => ({ id: `${idPrefix}${i}`, label: x.label, value: x.value }));
    if (rest.length) out.push({ id: `${idPrefix}more`, label: `${rest.length} other ${otherWord}`, value: rest.reduce((a, x) => a + x.value, 0), folded: rest.length });
    return out;
  }
  function insightsViews(res) {
    const S = (res && res.sections) || {}, rows = k => (S[k] && Array.isArray(S[k].rows) ? S[k].rows : []);
    const v = [];
    if (rows('web_action').concat(rows('web_location')).some(r => num(r.total) > 0)) v.push({ key: 'web', label: 'Web traffic: locations to actions' });
    if (rows('fw_action').some(r => num(r.total) > 0)) v.push({ key: 'fw', label: 'Firewall traffic by action' });
    if (rows('cloud_apps').some(r => num(r.data_consumed) > 0)) v.push({ key: 'apps', label: 'Cloud applications to sanctioned state' });
    return v;
  }
  function insightsFlowModel(res, view) {
    if (!res || !res.sections) return null;
    const views = insightsViews(res);
    if (!views.length) return { views, view: null, left: [], right: [], hub: null, links: [], summary: ['No section of this read has numbers to draw as a flow: each section below says why.'] };
    const key = views.some(x => x.key === view) ? view : views[0].key;
    const S = res.sections, rows = k => (S[k] && Array.isArray(S[k].rows) ? S[k].rows : []);
    let left = [], right = [], hub = null, links = [], unit = '', summary = [], fmtV = fmt;
    if (key === 'web') {
      unit = res.traffic_unit === 'BYTES' ? 'bytes' : 'transactions';
      if (unit === 'bytes') fmtV = bytes;
      left = fold(rows('web_location'), 'name', 'total', 'locations', 'loc:');
      const acts = rows('web_action'), all = acts.filter(r => r.action === 'ANY').map(r => num(r.total)).filter(v => v != null)[0];
      right = acts.filter(r => r.action !== 'ANY').map((r, i) => ({ id: `act:${i}`, label: r.name, value: num(r.total) || 0, tone: actionTone(r.action || r.name) })).filter(x => x.value > 0);
      const sl = left.reduce((a, x) => a + x.value, 0), sr = right.reduce((a, x) => a + x.value, 0);
      const total = Math.max(all || 0, sl, sr);
      // The tables are separate answers; where they differ the gap is drawn and named, never spread.
      if (total > sr) right.push({ id: 'act:other', label: all != null && all >= total ? 'Other actions (caution, isolate…)' : 'Action not reported', value: total - sr, gap: true, tone: 'warn' });
      if (total > sl) left.push({ id: 'loc:gap', label: 'Not attributed to a location', value: total - sl, gap: true });
      hub = { id: 'hub', label: 'Web traffic', value: total };
      left.forEach(x => links.push({ from: x.id, to: 'hub', value: x.value, tone: x.gap ? 'idle' : 'on' }));
      right.forEach(x => links.push({ from: 'hub', to: x.id, value: x.value, tone: x.tone }));
      summary.push(`Web traffic in ${unit}: ${fmtV(total)} in all. ${left.filter(x => !x.gap).map(x => `${x.label} ${fmtV(x.value)}`).join(', ') || 'No location numbers'} flow into ZIA, which ${right.filter(x => !x.gap).map(x => `${x.label.toLowerCase()} ${fmtV(x.value)}`).join(' and ') || 'reports no action numbers'}.`);
      right.filter(x => x.gap).forEach(x => summary.push(`${x.label}: ${fmtV(x.value)}, the part of all web traffic that is neither allowed nor blocked. Insights reports allowed and blocked only, so cautioned, isolated and other actions are not broken down.`));
      left.filter(x => x.gap).forEach(x => summary.push(`${x.label}: ${fmtV(x.value)}, the part of all web traffic the location table does not cover (it holds the top 50 locations).`));
      summary.push('Insights does not cross locations with actions, so each location flows into the same web traffic total rather than to a particular action.');
    } else if (key === 'fw') {
      unit = 'sessions';
      right = fold(rows('fw_action'), 'name', 'total', 'actions', 'fw:').map(x => Object.assign(x, { tone: x.folded ? 'warn' : actionTone(x.label) }));
      const total = right.reduce((a, x) => a + x.value, 0);
      left = [{ id: 'fw:src', label: 'Firewall sessions', value: total }];
      hub = null;
      right.forEach(x => links.push({ from: 'fw:src', to: x.id, value: x.value, tone: x.tone }));
      summary.push(`Firewall traffic: ${fmt(total)} sessions in all, ${right.map(x => `${x.label} ${fmt(x.value)}`).join(', ')}.`);
    } else {
      unit = 'bytes'; fmtV = bytes;
      const apps = rows('cloud_apps').map(r => ({ application: r.application, value: num(r.data_consumed), state: r.sanctioned_state || 'Not stated' })).filter(r => r.value != null && r.value > 0);
      left = fold(apps, 'application', 'value', 'applications', 'app:');
      const top = apps.slice().sort((a, b) => b.value - a.value);
      const keep = top.slice(0, SANKEY_MAX), rest = top.slice(SANKEY_MAX);
      const states = [];
      const stateId = s => { let i = states.findIndex(x => x.label === s); if (i < 0) { states.push({ id: `st:${states.length}`, label: s, value: 0, tone: sanctionTone(s) }); i = states.length - 1; } return states[i]; };
      keep.forEach((a, i) => { const st = stateId(a.state); st.value += a.value; links.push({ from: `app:${i}`, to: st.id, value: a.value, tone: st.tone }); });
      const restBy = {};
      rest.forEach(a => { const st = stateId(a.state); st.value += a.value; restBy[st.id] = (restBy[st.id] || 0) + a.value; });
      Object.keys(restBy).forEach(id => links.push({ from: 'app:more', to: id, value: restBy[id], tone: states.find(s => s.id === id).tone }));
      right = states;
      summary.push(`Cloud applications by data (bytes): ${left.map(x => `${x.label} ${bytes(x.value)}`).join(', ')}, flowing to ${states.map(s => `${s.label} ${bytes(s.value)}`).join(', ')}.`);
    }
    if (rows('top_users').length) summary.push('Users are not drawn: the users table counts security incidents per user, not traffic, and Insights cannot break traffic down by user.');
    const total = Math.max(left.reduce((a, x) => a + x.value, 0), right.reduce((a, x) => a + x.value, 0));
    return { views, view: key, unit, left, right, hub, links, total, summary };
  }

  // ── Bypass report: streams peeling off the path ─────────────────
  // The points in the order traffic meets them. ZPA bypass and PAC DIRECT
  // are not read by this report, so they are drawn as not measured.
  function bypassFlowModel(rep) {
    if (!rep) return null;
    const s = rep.summary || {}, secs = rep.sections || {}, zcc = secs.zcc || {};
    const n = k => Number(s[k]) || 0;
    const st = (sec, extra) => (sec && sec.not_in_scope ? 'not_read' : sec && (sec.status === 'unverified' || (sec.error && !(sec.count > 0))) ? 'unknown' : 'counted');
    const zParts = [['zcc_apps', 'apps'], ['zcc_processes', 'processes'], ['zcc_ips', 'IPs'], ['zcc_domains', 'domains'], ['zcc_trusted_nets', 'trusted networks']];
    const sslState = [secs.ssl_bypass_rules, secs.ssl_exemptions].every(x => x && x.not_in_scope) ? 'not_read' : [st(secs.ssl_bypass_rules), st(secs.ssl_exemptions)].indexOf('unknown') >= 0 ? 'unknown' : 'counted';
    const allowSecs = [secs.url_filter_allow, secs.firewall_allow, secs.dlp_allow];
    const allowState = allowSecs.every(x => x && x.not_in_scope) ? 'not_read' : allowSecs.some(x => st(x) === 'unknown') ? 'unknown' : 'counted';
    const points = [
      { key: 'zcc', label: 'Client Connector bypass', short: 'ZCC bypass', where: 'on the device', leaves: true, state: zcc.not_in_scope ? 'not_read' : st(zcc),
        value: zParts.reduce((a, [k]) => a + n(k), 0), parts: zParts.map(([k, l]) => [l, n(k)]),
        why: 'Apps, processes, IPs, domains and trusted networks that Client Connector sends direct: never tunnelled to Zscaler.' },
      { key: 'zpa', label: 'ZPA bypass', where: 'on the device', leaves: true, state: 'not_measured', value: null, parts: [],
        why: 'Not read by this report: the ZPA analysis page lists app segments whose bypass is ALWAYS or ON_NET.' },
      { key: 'pac', label: 'PAC DIRECT', where: 'in the browser', leaves: true, state: 'not_measured', value: null, parts: [],
        why: 'Not read by this report: the Path analyzer evaluates a PAC file for one destination and shows a DIRECT return.' },
      { key: 'ssl', label: 'SSL Do Not Inspect', where: 'in ZIA', leaves: false, state: sslState, value: n('ssl_bypass_rules') + n('ssl_exemptions'),
        parts: [['bypass rules', n('ssl_bypass_rules')], ['exemptions', n('ssl_exemptions')]],
        why: 'SSL inspection rules and exemptions that leave the traffic encrypted: it passes through Zscaler uninspected.' },
      { key: 'allow', label: 'Allow and DLP bypass rules', short: 'Allow / DLP bypass', where: 'in ZIA', leaves: false, state: allowState, value: n('url_filter_allow') + n('firewall_allow') + n('dlp_allow'),
        parts: [['URL allow', n('url_filter_allow')], ['firewall allow', n('firewall_allow')], ['DLP allow / bypass', n('dlp_allow')]],
        why: 'URL Filtering, firewall and DLP rules that allow or bypass: the traffic stays in Zscaler but that control lets it through.' },
    ];
    const drawn = points.reduce((a, p) => a + (p.value || 0), 0);
    const max = Math.max(1, ...points.map(p => p.value || 0));
    points.forEach(p => {
      p.share = p.value ? p.value / max : 0;
      p.text = p.state === 'not_measured' ? 'not measured here' : p.state === 'not_read' ? 'not read (out of scope)' : p.state === 'unknown' ? `could not be read${p.value ? `; ${plural(p.value, 'item')} read` : ''}` : plural(p.value, 'item');
    });
    const summary = [
      `Traffic leaves the device for the Zero Trust Exchange; at each point below a stream peels off. Stream widths are the report's counts of bypass items (rules, exemptions and entries), not traffic volume: ${plural(drawn, 'item')} drawn of ${plural(n('total_bypass_items'), 'bypass item')} in the report.`,
    ];
    points.forEach(p => summary.push(`${p.label} (${p.where}): ${p.text}${p.parts.length && p.state !== 'not_read' ? ` (${p.parts.map(([l, v]) => `${v} ${l}`).join(', ')})` : ''}. ${p.why}`));
    return { points, drawn, total: n('total_bypass_items'), risky: (rep.risk_flags || []).length, summary };
  }

  // ── Live DLP feed: one incident in words ────────────────────────
  const LIVE_WORD = { web: 'Inline web', endpoint: 'Endpoint', email: 'Email', saas: 'SaaS API', unknown: 'Unknown channel' };
  const ACTION_WORD = { enforced: 'configured to enforce', monitor: 'configured to monitor only', unknown: 'action not read' };
  function liveLine(m) {
    if (!m) return '';
    return `${LIVE_WORD[m.channel] || 'Unknown channel'} → ${m.dicts && m.dicts[0] ? `${m.dicts[0].name}${m.dicts[0].count != null ? ` (${m.dicts[0].count} matches)` : ''}` : 'dictionaries'} → ${m.engine || 'engine'} → rule ${m.rule ? `"${m.rule}"` : '(no rule name)'}, ${ACTION_WORD[m.enforcement] || ACTION_WORD.unknown} → incident receiver → Workflow Automation.`;
  }

  // ── Layouts: model → what to draw ───────────────────────────────
  // spec: {w, h, label, nodes: [{id, x, y, w, h, title, sub, tone}],
  //        links: [{from, to, ay, by, width, state, rate, tone, reason} | {d, …}],
  //        heads: [{x, y, text}]}
  function columnSpec(cols, links, label) {
    const W = 1000, BW = 200, gap = (W - 20 - cols.length * BW) / Math.max(1, cols.length - 1), RH = 56, TOP = 30;
    const rows = Math.max(1, ...cols.map(c => c.nodes.length));
    const H = TOP + rows * RH + 6;
    const nodes = [], heads = [];
    cols.forEach((c, ci) => {
      const x = 10 + ci * (BW + gap), off = (rows - c.nodes.length) * RH / 2;
      heads.push({ x, y: 16, text: `${c.label} (${c.nodes.length})` });
      c.nodes.forEach((n, ri) => nodes.push(Object.assign({}, n, { x, y: TOP + off + ri * RH, w: BW, h: 46, title: n.label })));
    });
    return { w: W, h: H, label, nodes, heads, links: links.map(l => Object.assign({ rate: l.state === 'flicker' ? 0.35 : 0.55 }, l)) };
  }
  function zpaInfraSpec(m) {
    return columnSpec(m.cols, m.links, 'ZPA connections: users and IdPs, the ZPA cloud, App Connector groups and app segments');
  }
  function sankeySpec(m) {
    const W = 1000, BW = 200, TOP = 30, GAP = 14, SCALE = m.total ? 120 / m.total : 0;
    const width = v => Math.max(2, v * SCALE);
    const colX = m.hub ? [10, 400, 790] : [10, 790];
    const stack = (list, x, extra) => {
      const hs = list.map(n => Math.max(46, width(n.value) + 8));
      return list.map((n, i) => ({ id: n.id, x, y: TOP + hs.slice(0, i).reduce((a, h) => a + h + GAP, 0), w: BW, h: hs[i], title: n.label, sub: (extra || (v => fmt(v)))(n.value), tone: n.tone || (n.gap ? 'idle' : 'on') }));
    };
    const f = m.unit === 'bytes' ? bytes : fmt;
    const L = stack(m.left, colX[0], f), R = stack(m.right, colX[colX.length - 1], f);
    const tall = list => (list.length ? list[list.length - 1].y + list[list.length - 1].h : TOP);
    let nodes = L.concat(R), H = Math.max(tall(L), tall(R));
    if (m.hub) {
      const hh = Math.max(46, width(m.hub.value) + 16);
      const hub = { id: 'hub', x: colX[1], y: TOP + (H - TOP - hh) / 2, w: 180, h: hh, title: m.hub.label, sub: f(m.hub.value), tone: 'on' };
      nodes = nodes.concat([hub]);
    }
    const by = {}; nodes.forEach(n => { by[n.id] = n; });
    // Each node's links leave and arrive stacked, so the streams add up visibly.
    const outY = {}, inY = {};
    nodes.forEach(n => { const tot = m.links.filter(l => l.from === n.id).reduce((a, l) => a + width(l.value), 0); outY[n.id] = n.y + (n.h - tot) / 2; const tin = m.links.filter(l => l.to === n.id).reduce((a, l) => a + width(l.value), 0); inY[n.id] = n.y + (n.h - tin) / 2; });
    const links = m.links.map(l => {
      const w = width(l.value), a = by[l.from], b = by[l.to];
      const ay = outY[l.from] + w / 2, byy = inY[l.to] + w / 2;
      outY[l.from] += w; inY[l.to] += w;
      return { from: l.from, to: l.to, ay, by: byy, width: w, value: l.value, state: l.tone === 'idle' ? 'idle' : 'live', tone: l.tone, rate: 0.15 + 2.2 * (m.total ? l.value / m.total : 0), reason: `${a.title} → ${b.title}: ${f(l.value)}` };
    });
    const heads = m.hub ? [{ x: colX[0], y: 16, text: m.view === 'web' ? 'Locations' : 'Source' }, { x: colX[1], y: 16, text: 'ZIA' }, { x: colX[2], y: 16, text: 'Action' }]
      : [{ x: colX[0], y: 16, text: m.view === 'apps' ? 'Cloud applications' : 'Source' }, { x: colX[1], y: 16, text: m.view === 'apps' ? 'Sanctioned state' : 'Action' }];
    return { w: W, h: H + 8, label: `Traffic flow (${m.unit}): ${m.summary[0] || ''}`, nodes, links, heads };
  }
  function bypassSpec(m) {
    const W = 1000, TY = 70, xs = [200, 350, 500, 650, 800], SY = 175;
    const nodes = [
      { id: 'device', x: 10, y: TY - 23, w: 120, h: 46, title: 'User device', sub: 'traffic starts', tone: 'on' },
      { id: 'inspected', x: 870, y: TY - 23, w: 120, h: 46, title: 'Inspected', sub: 'and enforced', tone: 'pass' },
    ];
    const links = [{ id: 'trunk', d: `M130 ${TY} H870`, width: 12, state: 'live', tone: 'on', rate: 1.1, reason: 'Traffic on its way through the Zero Trust Exchange (volume not measured)' }];
    m.points.forEach((p, i) => {
      const x = xs[i];
      const tone = p.state === 'counted' && p.value ? (p.leaves ? 'stop' : 'warn') : 'idle';
      nodes.push({ id: p.key, x: x - 68, y: SY, w: 136, h: 46, title: p.short || p.label, sub: p.text, tone });
      const w = p.state === 'counted' && p.value ? 3 + 20 * p.share : 2;
      links.push({ id: `peel:${p.key}`, d: `M${x} ${TY} C${x + 40} ${TY} ${x} ${TY + 55} ${x} ${SY}`, width: w,
        state: p.state === 'counted' ? (p.value ? 'live' : 'idle') : p.state === 'unknown' ? 'unknown' : 'idle', tone: p.leaves ? 'stop' : 'warn',
        rate: p.state === 'counted' && p.value ? 0.2 + 1.2 * p.share : 0, dashed: p.state !== 'counted', reason: `${p.label}: ${p.text}` });
    });
    const heads = [{ x: 150, y: 16, text: 'On the device and in the browser' }, { x: 580, y: 16, text: 'In the Zero Trust Exchange' }];
    return { w: W, h: SY + 56, label: 'Bypass streams: where traffic peels off the path through the Zero Trust Exchange', nodes, links, heads };
  }

  // ── Rendering (browser only) ────────────────────────────────────
  let seq = 0;
  function el(tag, attrs, text) {
    const e = root.document.createElement(tag);
    Object.keys(attrs || {}).forEach(k => e.setAttribute(k, attrs[k]));
    if (text != null) e.textContent = text;
    return e;
  }
  function list(ul, lines) { ul.textContent = ''; lines.forEach(t => ul.appendChild(el('li', {}, t))); }
  // Follow a change of the system's reduced-motion setting; returns the unsubscribe.
  function watchReduced(fn) {
    let q = null;
    try { q = root.matchMedia('(prefers-reduced-motion: reduce)'); } catch (e) { q = null; }
    if (!q || !q.addEventListener) return () => {};
    q.addEventListener('change', fn);
    return () => q.removeEventListener('change', fn);
  }
  // A motion toggle: the label says what a press does.
  function toggleHead(host, controls, title) {
    const head = el('div', { class: 'fp-head' });
    const btn = el('button', { type: 'button', class: 'rp-btn', 'aria-controls': controls }, 'Pause motion');
    const note = el('span', { class: 'fp-note' });
    if (title) head.appendChild(el('span', { class: 'fp-mode' }, title));
    head.appendChild(btn); head.appendChild(note);
    host.appendChild(head);
    return { btn, note };
  }

  // Draw a spec and keep packets moving on its links.
  function mountStream(host, spec, opts) {
    const FA = root.FA, o = opts || {}, id = `fp${++seq}`;
    host.textContent = '';
    const { btn, note } = toggleHead(host, `${id}-stage`, o.title);
    const stage = el('div', { class: 'fp-stage', id: `${id}-stage`, role: 'region', tabindex: '0', 'aria-label': `${o.region || 'Moving picture'}; it scrolls sideways inside this frame on a narrow window` });
    host.appendChild(stage);
    const sum = el('ul', { class: 'fp-summary', id: `${id}-sum` });
    host.appendChild(sum);
    list(sum, o.summary || []);
    const svg = FA.newSvg(stage, spec.w, spec.h, spec.label);
    svg.setAttribute('class', 'fa-svg fp-svg');
    svg.setAttribute('aria-describedby', `${id}-sum`);
    svg.removeAttribute('tabindex');
    (spec.heads || []).forEach(h => { const t = FA.svgEl('text', { x: h.x, y: h.y, class: 'fa-col' }, svg); t.textContent = h.text; });
    const by = {}; spec.nodes.forEach(n => { by[n.id] = n; });
    const linkG = FA.svgEl('g', { class: 'fp-links' }, svg);
    const L = spec.links.map(l => {
      let p;
      if (l.d) p = FA.svgEl('path', { d: l.d }, linkG);
      else {
        const a = by[l.from], b = by[l.to];
        const ay = l.ay != null ? l.ay : a.y + a.h / 2, byy = l.by != null ? l.by : b.y + b.h / 2;
        p = FA.curve(linkG, { x: a.x, y: ay, w: a.w, h: 0 }, { x: b.x, y: byy, w: 0, h: 0 });
      }
      p.setAttribute('class', `fp-link st-${l.state} tone-${l.tone || 'on'}${l.dashed ? ' dashed' : ''}`);
      p.setAttribute('stroke-width', String(l.width || 2));
      if (l.reason) { const t = FA.svgEl('title', {}, p); t.textContent = l.reason; }
      return { l, p, acc: Math.random(), len: 0 };
    });
    spec.nodes.forEach(n => FA.box(svg, n.x, n.y, n.w, n.h, n.title, n.sub, n.tone));
    const dotG = FA.svgEl('g', { class: 'fp-dots', 'aria-hidden': 'true' }, svg);
    const clock = FA.animator();
    const SPEED = 140, MAX = 160;
    // o.motion: the viewer's earlier Play / Pause choice (kept across redraws); o.onMotion is told of a new one.
    // o.optIn: the widths count items, not traffic, so motion adds nothing the still picture does not say:
    // it starts still and Play motion starts it (o.still says why).
    let dots = [], last = 0, stopJob = null, chosen = typeof o.motion === 'boolean' ? o.motion : null, dead = false;
    const playing = () => (chosen != null ? chosen : !o.optIn && !FA.reduced());
    function tick(now) {
      const dt = last ? Math.min(0.05, (now - last) / 1000) : 0; last = now;
      L.forEach(x => {
        if (!(x.l.rate > 0) || x.l.state === 'idle' || x.l.state === 'unknown') return;
        x.acc += dt * x.l.rate;
        while (x.acc >= 1) {
          x.acc -= 1;
          if (dots.length >= MAX) continue;
          if (!x.len) x.len = x.p.getTotalLength();
          const c = FA.svgEl('circle', { r: x.l.state === 'live' && x.l.width > 6 ? 4 : 3, class: `fa-dot fp-dot tone-${x.l.tone || 'on'}` }, dotG);
          dots.push({ x, d: 0, c, popped: 0 });
        }
      });
      dots = dots.filter(b => {
        if (b.popped) { b.popped -= dt; if (b.popped <= 0) { b.c.remove(); return false; } return true; }
        b.d += SPEED * dt;
        const end = b.x.l.state === 'stop' ? b.x.len * 0.5 : b.x.len;
        if (b.d >= end) {
          if (b.x.l.state === 'stop') { b.c.setAttribute('class', 'fa-dot fp-dot bad pop'); b.popped = 0.45; return true; }
          b.c.remove(); return false;
        }
        const q = b.x.p.getPointAtLength(b.d);
        b.c.setAttribute('cx', q.x.toFixed(1)); b.c.setAttribute('cy', q.y.toFixed(1));
        return true;
      });
    }
    // Motion starts in its steady state: each moving link already carries
    // the packets it would hold after running a while (spaced SPEED / rate
    // apart, phased by its own random start), so a picture that says it is
    // moving is never empty for the first second or more of a slow link.
    function warm() {
      L.forEach(x => {
        if (!(x.l.rate > 0) || x.l.state === 'idle' || x.l.state === 'unknown') return;
        if (!x.len) x.len = x.p.getTotalLength();
        const end = x.l.state === 'stop' ? x.len * 0.5 : x.len;
        for (let k = 0; dots.length < MAX; k++) {
          const d = SPEED * (k + x.acc) / x.l.rate;
          if (d >= end) break;
          const q = x.p.getPointAtLength(d);
          const c = FA.svgEl('circle', { r: x.l.state === 'live' && x.l.width > 6 ? 4 : 3, class: `fa-dot fp-dot tone-${x.l.tone || 'on'}`, cx: q.x.toFixed(1), cy: q.y.toFixed(1) }, dotG);
          dots.push({ x, d, c, popped: 0 });
        }
      });
    }
    function sync() {
      const on = playing() && !dead;
      btn.textContent = on ? 'Pause motion' : 'Play motion';
      stage.classList.toggle('fp-moving', on);
      note.textContent = on ? (o.moving || 'Packets move along each link; the list below says the same in words.')
        : (FA.reduced() && chosen == null ? 'Motion is off because your system asks for reduced motion. Play motion starts it.'
          : o.optIn && chosen == null ? (o.still || 'The picture is still: its widths say it all. Play motion starts it.') : 'Motion paused.');
      if (on && !stopJob) { last = 0; warm(); stopJob = clock.add(tick); }
      if (!on && stopJob) { stopJob(); stopJob = null; dots.forEach(b => b.c.remove()); dots = []; }
    }
    btn.addEventListener('click', () => { chosen = !playing(); if (o.onMotion) o.onMotion(chosen); sync(); });
    const mq = watchReduced(() => { if (chosen == null) sync(); });
    sync();
    return {
      playing, svg, stage, button: btn,
      dots: () => dots.length,
      destroy() { dead = true; mq(); clock.destroy(); dots = []; host.textContent = ''; },
    };
  }

  // The diagnosis walk on FA.hopPlayer, with Play, Step and Stop, and the
  // walk in words (the current step marked as it lands).
  function mountWalk(host, model, opts) {
    const FA = root.FA, o = opts || {}, id = `fp${++seq}`;
    host.textContent = '';
    const head = el('div', { class: 'fp-head' });
    const play = el('button', { type: 'button', class: 'rp-btn', 'aria-controls': `${id}-stage` }, 'Play the walk');
    const step = el('button', { type: 'button', class: 'rp-btn', 'aria-controls': `${id}-stage` }, 'Step');
    const stop = el('button', { type: 'button', class: 'rp-btn', 'aria-controls': `${id}-stage` }, 'Stop');
    const note = el('span', { class: 'fp-note', role: 'status' });
    [play, step, stop, note].forEach(x => head.appendChild(x));
    host.appendChild(head);
    const stage = el('div', { class: 'fp-stage', id: `${id}-stage`, role: 'region', tabindex: '0', 'aria-label': `${o.region || 'The decision, step by step'}; it scrolls sideways inside this frame on a narrow window` });
    host.appendChild(stage);
    const log = el('ol', { class: 'fa-log fp-walk', id: `${id}-log` });
    host.appendChild(log);
    model.hops.forEach((h, i) => log.appendChild(el('li', { 'data-i': String(i) }, `${h.label}${h.sub && h.key !== 'rule' ? ` (${h.sub})` : ''}: ${h.note || h.sub || ''}`)));
    const mark = i => log.querySelectorAll('li').forEach(li => li.classList.toggle('cur', Number(li.dataset.i) === i));
    const p = FA.hopPlayer(stage, model, {
      onHop(h, i) { mark(i); note.textContent = `${h.label}: ${h.sub || ''}`; },
      onReset() { mark(0); note.textContent = ''; },
      onDone() { note.textContent = model.verdict.text; },
    });
    const svg = stage.querySelector('svg');
    if (svg) { svg.setAttribute('aria-describedby', `${id}-log`); svg.removeAttribute('tabindex'); }
    play.addEventListener('click', () => p.play());
    step.addEventListener('click', () => p.step());
    stop.addEventListener('click', () => p.reset());
    // Moves on its own only when motion is welcome; else the final state, still.
    p.play();
    return { player: p, destroy() { p.destroy(); host.textContent = ''; } };
  }

  // The Live DLP feed's lanes: FA.live with a pause, the incident receiver
  // as the last stop, and the incidents in words (newest first, 12 kept).
  function mountLive(host, opts) {
    const FA = root.FA, o = opts || {}, id = `fp${++seq}`;
    host.textContent = '';
    const { btn, note } = toggleHead(host, `${id}-stage`, o.title);
    const stage = el('div', { class: 'fp-stage', id: `${id}-stage`, role: 'region', tabindex: '0', 'aria-label': 'Each incident as it lands; it scrolls sideways inside this frame on a narrow window' });
    host.appendChild(stage);
    const tally = el('p', { class: 'fp-tally' }, 'No incident yet this session: the lanes wait for the first one.');
    host.appendChild(tally);
    const log = el('ol', { class: 'fa-log fp-livelog', id: `${id}-log`, 'aria-label': 'The latest incidents, in words' });
    host.appendChild(log);
    const lanes = FA.live(stage, { sink: { title: 'Incident', sub: 'receiver → WA' } });
    const svg = stage.querySelector('svg');
    if (svg) { svg.setAttribute('aria-describedby', `${id}-log`); svg.removeAttribute('tabindex'); }
    let chosen = null, seen = 0;
    const playing = () => (chosen != null ? chosen : !FA.reduced());
    function sync() {
      btn.textContent = playing() ? 'Pause motion' : 'Play motion';
      lanes.setMotion(chosen == null ? null : chosen);
      note.textContent = playing() ? 'Each incident flies through its lanes as it lands.' : (FA.reduced() && chosen == null ? 'Motion is off because your system asks for reduced motion: each incident lands at once. Play motion starts it.' : 'Motion paused: each incident lands at once.');
    }
    btn.addEventListener('click', () => { chosen = !playing(); sync(); });
    const mq = watchReduced(() => { if (chosen == null) sync(); });
    sync();
    function push(inc) {
      const m = FA.liveModel(inc);
      if (!m) return Promise.resolve();
      seen++;
      log.insertBefore(el('li', {}, liveLine(m)), log.firstChild);
      while (log.children.length > 12) log.removeChild(log.lastChild);
      const done = lanes.push(m);
      const c = lanes.counts();
      return done.then(() => {
        const k = lanes.counts();
        const landed = k.enforced + k.monitor + k.unknown_action;
        tally.textContent = `${plural(landed, 'incident')} through the lanes this session${landed < seen ? ` (${seen - landed} more on the way)` : ''}: ${k.enforced} configured to enforce, ${k.monitor} monitor only, ${k.unknown_action} with the action not read. Actions are the rule's current configuration, not proof of what happened.`;
        return k;
      }).catch(() => c);
    }
    return { push, counts: () => lanes.counts(), idle: () => lanes.idle(), playing, button: btn, destroy() { mq(); lanes.destroy(); host.textContent = ''; } };
  }

  const FP = {
    zpaInfraModel, zpaDiagModel, insightsFlowModel, insightsViews, bypassFlowModel, liveLine,
    zpaInfraSpec, sankeySpec, bypassSpec, mountStream, mountWalk, mountLive,
  };
  root.FP = FP;
  if (typeof module !== 'undefined' && module.exports) module.exports = FP;
})(typeof window !== 'undefined' ? window : globalThis);
