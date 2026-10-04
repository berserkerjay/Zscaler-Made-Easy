// ── Path motion: the DLP chain, end to end, with moving bits ────────
// The live picture on the Path analyzer page. It draws the chain from the
// Data Security Architect reference (/reference/data-security-architect
// #chain, "The chain, end to end"): content is captured on a channel, a
// dictionary reports a match count, an engine turns counts into a verdict
// (Boolean expression, match counts, the Channels gate, at most four
// engines per rule), one of the five channel rule types acts on it, and
// then the rule forwards on its own:
//   - the evidence lane: the rule's forwarding setting (Incident Receiver
//     or cloud-to-cloud) → customer-owned storage (-data and -metadata
//     buckets) → a storage event → the WA "DLP Application Integration"
//     → Workflow Automation, which reads the metadata only;
//   - the telemetry lane: channel logs → NSS / Cloud NSS → SIEM, which
//     never feeds Workflow Automation;
//   - auditor email and third-party ICAP: parallel paths that never feed
//     it either; DSPM has its own alert flow and is not a WA source.
// Before a result exists the reference chain idles with bits on every
// lane. With a result (the same JSON the page already renders: trace,
// verdict, channels) the bits follow the path that result describes and
// stop where it stops, with the broken link marked and said in words.
// Pure DOM + inline SVG + requestAnimationFrame; no tenant reads. Motion
// honours prefers-reduced-motion (static arrows, Play to start it).

const _pmE = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const PM_SVGNS = 'http://www.w3.org/2000/svg';
// Names in the summary (the chain's text alternative) are capped the way
// the hop detail caps them, so a tenant with hundreds of rules still gets
// a description a screen reader can read out.
const PM_LIST_MAX = 5;
function _pmList(names, max) {
  const n = max || PM_LIST_MAX, all = (names || []).map(x => String(x == null ? '' : x));
  return all.length > n ? `${all.slice(0, n).join(', ')}, … and ${all.length - n} more` : all.join(', ');
}
const PM_TOP = 30, PM_W = 150, PM_H = 44, PM_BUS = 752;
// Each stage of the chain. x/y are the box's top-left corner (before the
// caption row). `col` groups them under the column captions.
const PM_NODES = [
  { key: 'cap_web', x: 10, y: 20, label: 'Inline web', sub: 'ZCC tunnel → SSL decrypt' },
  { key: 'cap_ep', x: 10, y: 95, label: 'Endpoint', sub: 'on the device' },
  { key: 'cap_mail', x: 10, y: 170, label: 'Email', sub: 'outbound mail' },
  { key: 'cap_saas', x: 10, y: 245, label: 'SaaS API', sub: 'files at rest' },
  { key: 'dict', x: 200, y: 132, label: 'Dictionaries', sub: 'typed · confidence · count' },
  { key: 'engine', x: 385, y: 132, label: 'DLP engine', sub: 'Boolean · Channels gate' },
  { key: 'r_web', x: 575, y: 20, label: 'Inline Web DLP rule', sub: 'needs SSL decryption' },
  { key: 'r_ep', x: 575, y: 95, label: 'Endpoint DLP rule', sub: 'runs on the device' },
  { key: 'r_mail', x: 575, y: 170, label: 'Email DLP rule', sub: 'Zscaler-tagged mail' },
  { key: 'r_saas', x: 575, y: 245, label: 'SaaS API DLP rule', sub: 'scans at rest' },
  { key: 'r_dspm', x: 575, y: 340, label: 'DSPM', sub: 'separate alert flow' },
  { key: 'logs', x: 780, y: 20, label: 'Channel logs', sub: 'kept in Zscaler' },
  { key: 'auditor', x: 780, y: 95, label: 'Auditor email', sub: 'notify · never feeds WA' },
  { key: 'evid', x: 780, y: 170, label: 'Evidence forwarding', sub: 'Incident Receiver / C2C' },
  { key: 'icap', x: 780, y: 245, label: '3rd-party ICAP', sub: 'copy · never feeds WA' },
  { key: 'dspma', x: 780, y: 340, label: 'DSPM alerts', sub: 'not a WA source' },
  { key: 'nss', x: 965, y: 20, label: 'NSS / Cloud NSS', sub: 'streams logs out' },
  { key: 'storage', x: 965, y: 170, label: 'Customer storage', sub: '-metadata + -data buckets' },
  { key: 'siem', x: 1150, y: 20, label: 'SIEM', sub: 'archive' },
  { key: 'event', x: 1150, y: 170, label: 'Storage event', sub: 'SNS / Event Grid' },
  { key: 'waint', x: 1150, y: 255, label: 'WA integration', sub: 'Enabled · metadata only' },
  { key: 'wa', x: 1150, y: 340, label: 'Workflow Automation', sub: 'incidents · triage' },
];
const PM_COLS = [[10, 'Captured'], [200, 'Dictionary'], [385, 'Engine'], [575, 'Channel rule'], [780, 'Forwarding'], [965, 'Out of Zscaler'], [1150, 'Destination']];
const PM_CHANNELS = [
  { ch: 'web', trace: null, label: 'Inline Web DLP' },
  { ch: 'ep', trace: 'endpoint', label: 'Endpoint DLP' },
  { ch: 'mail', trace: 'email', label: 'Email DLP' },
  { ch: 'saas', trace: 'saas', label: 'SaaS Security API DLP' },
];
// The lanes after a channel rule, by name, as edge lists.
const PM_LANE = {
  tel: ['logs>nss', 'nss>siem'],
  ev: ['evid>storage', 'storage>event', 'event>waint', 'waint>wa'],
};
// How a stop is marked, by tone: a break, a policy block, a rule list that
// could not be read (a failed or rate-limited read is not "no rule"), and a
// part left out of scope on the Scope page (not read, so neither of those).
const PM_MARK = { broken: '✕', blocked: '■', unread: '?', scope: '–' };
const PM_CUT_CLS = ['is-broken', 'is-blocked', 'is-unread', 'is-scope'];
const PM_W_TOTAL = 1150 + PM_W + 10, PM_H_TOTAL = PM_TOP + 340 + PM_H + 22;

function _pmNode(k) { return PM_NODES.find(n => n.key === k); }
function _pmChain(ch) { return [`cap_${ch}>dict`, 'dict>engine', `engine>r_${ch}`]; }
// Which lane an edge belongs to: its colour and its legend entry.
function _pmLane(e) {
  if (/^r_dspm|^dspma|>dspma/.test(e)) return 'dspm';
  if (/>logs$|^logs>|^nss>/.test(e)) return 'tel';
  if (/>auditor$|>icap$/.test(e)) return 'par';
  if (/>evid$|^evid>|^storage>|^event>|^waint>/.test(e)) return 'ev';
  return 'main';
}

// Every route the reference chain carries: each channel's content through
// dictionaries and engine to its own rule, then out of the rule on each
// lane. Web DLP is the rule type with a third-party ICAP option.
function _pmReferenceRoutes() {
  const routes = [];
  PM_CHANNELS.forEach(({ ch }) => {
    const base = _pmChain(ch);
    routes.push({ edges: base.concat([`r_${ch}>logs`], PM_LANE.tel) });
    routes.push({ edges: base.concat([`r_${ch}>auditor`]) });
    routes.push({ edges: base.concat([`r_${ch}>evid`], PM_LANE.ev) });
    if (ch === 'web') routes.push({ edges: base.concat(['r_web>icap']) });
  });
  routes.push({ edges: ['dict>engine', 'engine>r_dspm', 'r_dspm>dspma'] });
  return routes;
}
const PM_EDGES = (() => {
  const seen = [];
  _pmReferenceRoutes().forEach(r => r.edges.forEach(e => { if (!seen.includes(e)) seen.push(e); }));
  return seen;
})();

// The Live DLP feed's model: the session's Workflow Automation incidents
// (each already through dictionaries, an engine and a channel rule, and
// forwarded as evidence, or Workflow Automation would not have it). Each
// channel that raised one carries bits through its rule and the evidence
// lane at a rate that follows its count; the rest idle. Its rule is tagged
// ENFORCE when every incident on it was enforced, MONITOR when any was
// only logged. Only counts and rule / dictionary names are used: no user
// or file name reaches the picture or its summary.
const PM_LIVE_CH = { web: 'web', endpoint: 'ep', email: 'mail', saas: 'saas' };
function pmLiveModel(incidents) {
  const by = {};
  let other = 0;
  (incidents || []).forEach(i => {
    const ch = PM_LIVE_CH[i && i.channel];
    if (!ch) { other++; return; }
    const c = by[ch] || (by[ch] = { n: 0, enforced: 0, monitor: 0, unknown: 0, rules: {}, dicts: {} });
    c.n++;
    c[i.enforcement === 'enforced' ? 'enforced' : i.enforcement === 'monitor' ? 'monitor' : 'unknown']++;
    (i.rules || []).forEach(r => { c.rules[r] = (c.rules[r] || 0) + 1; });
    (i.dictionaries || []).forEach(d => { if (d && d.name) c.dicts[d.name] = (c.dicts[d.name] || 0) + (Number(d.count) || 0); });
  });
  const top = o => Object.keys(o).sort((a, b) => o[b] - o[a]);
  const routes = [], summary = [], extra = {};
  const total = Object.keys(by).reduce((a, k) => a + by[k].n, 0);
  summary.push(`${total} incident${total === 1 ? '' : 's'} this session${other ? ` (and ${other} on a channel the chain does not draw)` : ''}. Each one was matched by dictionaries, turned into a verdict by an engine, acted on by a channel rule and forwarded as evidence: Workflow Automation only has incidents whose rule forwards evidence.`);
  PM_CHANNELS.forEach(({ ch, label }) => {
    const base = _pmChain(ch), c = by[ch];
    if (!c) {
      routes.push({ edges: base, stop: null, tone: null, rate: 0.06 });
      summary.push(`${label}: no incident this session.`);
      return;
    }
    const rate = Math.min(1.4, 0.3 + c.n * 0.1);
    routes.push({ edges: base.concat([`r_${ch}>evid`], PM_LANE.ev), stop: null, tone: null, rate });
    routes.push({ edges: base.concat([`r_${ch}>logs`], PM_LANE.tel), stop: null, tone: null, rate: rate / 3 });
    extra[`r_${ch}`] = c.monitor ? 'monitor' : (c.enforced ? 'enforce' : undefined);
    const rules = top(c.rules), dicts = top(c.dicts);
    summary.push(`${label}: ${c.n} incident${c.n === 1 ? '' : 's'}, ${c.enforced} enforced, ${c.monitor} monitor-only${c.unknown ? `, ${c.unknown} with the rule's action not read` : ''}.`
      + (rules.length ? ` Rules: ${_pmList(rules.map(r => `${r} (${c.rules[r]})`))}.` : '')
      + (dicts.length ? ` Dictionaries: ${_pmList(dicts.map(d => `${d} (${c.dicts[d]} matches)`))}.` : '')
      + (c.monitor ? ' Monitor-only matches are logged and forwarded but the data still left.' : ''));
  });
  summary.push('Telemetry lane: each match also writes a channel log that NSS / Cloud NSS can stream to the SIEM; this feed does not read NSS, and that lane never feeds Workflow Automation.');
  return { mode: 'live', routes, stops: [], summary, extra };
}

// The model: from an analyzer result (or none) to the routes the bits
// take, where each one stops and why, and a plain-words summary. Pure, so
// the page and the tests share it. {live: [incidents]} is the Live DLP
// feed's session (pmLiveModel).
function pmModel(res) {
  if (res && Array.isArray(res.live) && res.live.length) return pmLiveModel(res.live);
  if (!res || !res.trace) {
    return {
      mode: 'reference', routes: _pmReferenceRoutes().map(r => Object.assign(r, { stop: null, tone: null, rate: 0.22 })),
      summary: [
        'The reference chain, idling: content is captured on a channel (inline web, endpoint, email, SaaS at rest), dictionaries report match counts, the DLP engine turns them into a verdict and passes it only to the rule types ticked in its Channels gate, and the channel rule acts.',
        'Evidence lane: the rule\'s forwarding setting (Incident Receiver or cloud-to-cloud) writes evidence and metadata to customer-owned storage; a storage event wakes the Workflow Automation integration, which reads the metadata only.',
        'Telemetry lane: channel logs stream through NSS / Cloud NSS to the SIEM and never feed Workflow Automation. Auditor email and third-party ICAP are parallel paths that never feed it either; DSPM raises its own alerts.',
      ],
      stops: [], extra: {},
    };
  }
  const t = res.trace, v = res.verdict || {}, hops = t.hops || [];
  const hop = k => hops.find(h => h.key === k) || null;
  const routes = [], stops = [], summary = [], extra = {};
  const name = h => (h && h.decided_by && h.decided_by.name) || '';
  const stopRoute = (edges, at, tone, reason, rate) => {
    routes.push({ edges, stop: at, tone, rate: rate || 0.5 });
    stops.push({ edge: edges[at], tone, reason });
  };

  // 1. Inline web: the path this analysis traced.
  const web = _pmChain('web');
  const out = v.outcome || t.outcome;
  if (out === 'bypassed') {
    const why = `Never reaches Zscaler: ${v.stops_at || 'the forwarding decision'}${v.blocked_by ? ` '${v.blocked_by}'` : ''} sends it direct, so no dictionary ever sees the content.`;
    stopRoute(web, 0, 'broken', why, 0.6);
    summary.push(`Inline web: ${why}`);
  } else if (out === 'blocked') {
    const why = `Blocked by ${v.stops_at || 'policy'}${v.blocked_by ? ` rule '${v.blocked_by}'` : ''} before any content scan: nothing leaves, so nothing reaches a dictionary.`;
    stopRoute(web, 0, 'blocked', why, 0.6);
    summary.push(`Inline web: ${why}`);
  } else if (out === 'blind') {
    const ssl = hop('ssl');
    const why = `Left encrypted${name(ssl) ? ` by SSL inspection rule '${name(ssl)}'` : ' (no SSL inspection rule decrypts it)'}: dictionaries never see the content, so no engine or rule can match.`;
    stopRoute(web, 0, 'broken', why, 0.6);
    summary.push(`Inline web: ${why}`);
  } else if (out === 'unknown') {
    // A failed or rate-limited read is not "no rule": marked as unread (?),
    // never as a break.
    const ssl = hop('ssl'), dlp = hop('dlp');
    const sslUnread = !!(ssl && ssl.status === 'unknown');
    const why = `Could not be read: ${(sslUnread ? ssl.detail : dlp && dlp.detail) || 'the Web DLP rules could not be read, so whether a rule covers this traffic is unknown.'}`;
    stopRoute(web, sslUnread ? 0 : 2, 'unread', why, 0.6);
    summary.push(`Inline web: ${why}`);
  } else if (out === 'out_of_scope') {
    // Left out on the Scope page: not read, so not "no rule" and not
    // "could not read". Marked where the part out of scope sits.
    const ssl = hop('ssl'), dlp = hop('dlp');
    const sslOut = !!(ssl && ssl.status === 'out_of_scope');
    const why = `Not in scope: ${(sslOut ? ssl.detail : dlp && dlp.detail) || 'the Web DLP rules are not in scope on the Scope page, so this part of the chain is not assessed.'}`.replace(/^Not in scope: Not in scope: /, 'Not in scope: ');
    stopRoute(web, sslOut ? 0 : 2, 'scope', why, 0.6);
    summary.push(`Inline web: ${why}`);
  } else if (out === 'none') {
    const why = 'Decrypted, but no enabled Web DLP rule targets this traffic: no engine verdict is ever acted on, logged as a DLP match or forwarded.';
    stopRoute(web, 2, 'broken', why, 0.6);
    summary.push(`Inline web: ${why}`);
  } else if (out === 'enforce' || out === 'monitor') {
    const dlp = hop('dlp') || {}, rules = dlp.rules || [];
    // No flatMap: an older browser must still get the result (ES2017).
    const engines = [...new Set(rules.reduce((a, r) => a.concat(r.engines || []), []))];
    if (rules.length && !engines.length) {
      const why = `The covering rule(s) (${_pmList(rules.map(r => r.name))}) name no DLP engine: no dictionary count becomes a verdict.`;
      stopRoute(web, 2, 'broken', why, 0.6);
      summary.push(`Inline web: ${why}`);
    } else {
      const over = rules.filter(r => (r.engines || []).length > 4);
      summary.push(`Inline web: decrypted; ${rules.length} Web DLP rule(s) ${out === 'enforce' ? 'inspect and can block' : 'inspect but only monitor'} it, through ${engines.length} engine(s): ${_pmList(engines) || 'none named'}.`
        + (over.length ? ` ${_pmList(over.map(r => r.name))} reference more than four engines, the per-rule limit.` : ''));
      extra.r_web = out;
      // Telemetry: every match is logged; NSS / SIEM are not read here.
      routes.push({ edges: web.concat(['r_web>logs'], PM_LANE.tel), stop: null, tone: null, rate: 0.35 });
      summary.push('Telemetry lane: each match writes a DLP log that NSS / Cloud NSS can stream to the SIEM (the NSS feeds are not read by this analysis). It never feeds Workflow Automation.');
      const inc = hop('incident') || {};
      const notifiers = inc.notifiers || [];
      if (notifiers.length) {
        routes.push({ edges: web.concat(['r_web>auditor']), stop: null, tone: null, rate: 0.25 });
        summary.push(`Auditor email: notified by ${_pmList(notifiers)} (a parallel path; it never feeds Workflow Automation).`);
      } else {
        summary.push('Auditor email: no covering rule notifies an auditor.');
      }
      const ir = rules.filter(r => r.incident_receiver), icap = rules.filter(r => r.icap_server && !r.incident_receiver);
      if (ir.length) {
        routes.push({ edges: web.concat(['r_web>evid'], PM_LANE.ev), stop: null, tone: null, rate: 0.5 });
        summary.push(`Evidence lane: ${_pmList(ir.map(r => r.name))} → the Zscaler Incident Receiver: the match and the file are forwarded, so the evidence can reach customer storage and Workflow Automation (the storage bucket and the WA integration are not read here; they must exist and be Enabled).`);
      } else if (icap.length) {
        routes.push({ edges: web.concat(['r_web>evid'], PM_LANE.ev), stop: null, tone: 'assumed', rate: 0.4 });
        extra.assumed = ['r_web>evid'];
        summary.push(`Evidence lane: ${_pmList(icap.map(r => r.name))} → an ICAP server only. That reaches Workflow Automation only if the ICAP server is a Zscaler Incident Receiver VM; a third-party ICAP server is a parallel path that never feeds it.`);
      } else {
        const why = 'No covering rule forwards evidence (Incident Receiver or cloud-to-cloud): the most-missed link. Matches stay in the logs and Workflow Automation stays empty.';
        stopRoute(web.concat(['r_web>evid'], PM_LANE.ev), 3, 'broken', why, 0.5);
        summary.push(`Evidence lane: ${why}`);
      }
      if (rules.some(r => r.icap_server)) {
        routes.push({ edges: web.concat(['r_web>icap']), stop: null, tone: null, rate: 0.25 });
        summary.push(`ICAP: a copy also goes to an ICAP server from ${_pmList(rules.filter(r => r.icap_server).map(r => r.name))}.`);
      }
    }
  }
  // A Cloud App Control or File Type Control block (an upload blocked
  // before DLP) is policy blocking part of this traffic, whatever the DLP
  // outcome: a ■ on the way in, and said in words.
  if (v.stops_at && out !== 'bypassed' && out !== 'blocked') {
    const why = `${v.stops_at}${v.blocked_by ? ` '${v.blocked_by}'` : ''} blocks part of this traffic (such as uploads) before DLP (see "What blocks this traffic").`;
    if (!stops.some(s => s.edge === web[0])) stopRoute([web[0]], 0, 'blocked', why, 0.3);
    summary.push(`On the way: ${why}`);
  }

  // 2. The parallel channels: how far each gets for the same data. What
  //    their rules forward is not traced by this analysis.
  PM_CHANNELS.filter(c => c.trace).forEach(({ ch, trace, label }) => {
    const c = (t.channels || {})[trace];
    if (!c) return;
    const base = _pmChain(ch);
    if (c.status === 'enforce' || c.status === 'monitor') {
      routes.push({ edges: base, stop: null, tone: null, rate: 0.22 });
      extra[`r_${ch}`] = c.status;
      summary.push(`${label}: ${c.detail || ''} ${c.status === 'enforce' ? 'Enforcing' : 'Monitor only'}; what its rules forward is not traced here.`.replace(/\s+/g, ' ').trim());
    } else if (c.status === 'unknown') {
      const why = `${label}: could not be read. ${c.detail || ''}`.replace(/\s+/g, ' ').trim();
      stopRoute(base, 2, 'unread', why, 0.22);
      summary.push(why);
    } else if (c.status === 'out_of_scope') {
      const why = `${label}: ${c.detail || 'not in scope on the Scope page, so not read.'}`.replace(/\s+/g, ' ').trim();
      stopRoute(base, 2, 'scope', why, 0.22);
      summary.push(why);
    } else if (c.status === 'off') {
      const why = `${label}: ${c.detail || 'rules exist but the channel is not active on this device.'}`;
      stopRoute(base, 0, 'broken', why, 0.22);
      summary.push(why);
    } else {
      const why = `${label}: ${c.detail || 'no enabled rule.'}`;
      stopRoute(base, 2, 'broken', why, 0.22);
      summary.push(why);
    }
  });
  summary.push('DSPM: not part of this analysis (a separate alert flow that is not a Workflow Automation source).');
  return { mode: 'result', routes, stops, summary, extra };
}

// Edge geometry: left to right between columns, straight down within the
// last column, and through the forwarding bus out of a channel rule.
function _pmEdgeD(key) {
  const [a, b] = key.split('>').map(_pmNode);
  const ay = a.y + PM_TOP, by = b.y + PM_TOP;
  if (a.x === b.x) return `M${a.x + PM_W / 2},${ay + PM_H} L${b.x + PM_W / 2},${by}`;
  const x1 = a.x + PM_W, y1 = ay + PM_H / 2, x2 = b.x, y2 = by + PM_H / 2;
  if (a.key.startsWith('r_') && a.key !== 'r_dspm') return `M${x1},${y1} H${PM_BUS} V${y2} H${x2}`;
  const mx = (x1 + x2) / 2;
  return `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
}

// Where on an edge a stop is marked (and where its bits pop). A rule's
// forwarding edges share the vertical bus, so a mark at the middle of
// r_web>evid would sit on the stretch it shares with r_web>auditor, right
// at the auditor's junction, and read as if that live link were broken.
// Those stops go on the edge's own last stretch into its target instead.
function _pmStopLen(key, L) {
  const [a, b] = key.split('>').map(_pmNode);
  if (a.key.startsWith('r_') && a.key !== 'r_dspm' && a.y !== b.y) return Math.max(L / 2, L - (b.x - PM_BUS) / 2);
  return L / 2;
}

// The stretch of a broken or blocked edge that is its own. A rule's
// forwarding edges all leave it along the same stub to the bus and run down
// the same bus, so drawing the whole broken edge would paint the live
// telemetry and auditor links beside it as broken too. With `live` (the
// edges still carrying bits) it returns only what no live sibling from the
// same rule also draws: the bus below the last live junction and the run
// into the edge's own target. With no live sibling it is the whole edge.
function _pmOwnD(key, live) {
  const [a, b] = key.split('>').map(_pmNode);
  if (!a.key.startsWith('r_') || a.key === 'r_dspm' || a.x === b.x) return _pmEdgeD(key);
  const mid = n => n.y + PM_TOP + PM_H / 2, y1 = mid(a), y2 = mid(b), dir = Math.sign(y2 - y1);
  let shared = -1;
  (live || []).forEach(k => {
    const [sa, sb] = k.split('>');
    if (sa !== a.key || k === key || !_pmNode(sb)) return;
    const d = mid(_pmNode(sb)) - y1;
    shared = Math.max(shared, dir !== 0 && Math.sign(d) === dir ? Math.min(Math.abs(d), Math.abs(y2 - y1)) : 0);
  });
  if (shared < 0) return _pmEdgeD(key);
  return `M${PM_BUS},${y1 + dir * shared} V${y2} H${b.x}`;
}

function _pmSvg() {
  const cols = PM_COLS.map(([x, l]) => `<text class="pm-col" x="${x + 2}" y="14">${_pmE(l.toUpperCase())}</text>`).join('');
  const edges = PM_EDGES.map(e => `<path class="pm-edge lane-${_pmLane(e)}" data-edge="${_pmE(e)}" d="${_pmEdgeD(e)}" marker-end="url(#pmArrow)"/>`).join('');
  const nodes = PM_NODES.map(n => `<g class="pm-node" data-node="${n.key}" transform="translate(${n.x},${n.y + PM_TOP})">
      <rect class="box" width="${PM_W}" height="${PM_H}" rx="10"/>
      <text class="lbl" x="10" y="18">${_pmE(n.label)}</text>
      <text class="sub" x="10" y="34">${_pmE(n.sub)}</text>
      <text class="tag" x="${PM_W - 4}" y="-4" text-anchor="end"></text>
    </g>`).join('');
  // The telemetry lane's dead end: SIEM never hands anything to WA.
  const sx = 1150 + PM_W / 2, never = `<g class="pm-never" aria-hidden="true">
      <path d="M${sx},${20 + PM_TOP + PM_H} V${170 + PM_TOP}"/>
      <text class="pm-x" x="${sx}" y="${(20 + PM_H + 170) / 2 + PM_TOP + 4}" text-anchor="middle">✕</text>
      <text class="pm-note" x="${sx - 8}" y="${(20 + PM_H + 170) / 2 + PM_TOP + 20}" text-anchor="end">never feeds WA</text>
    </g>
    <text class="pm-note" x="965" y="${20 + PM_TOP + PM_H + 16}">telemetry lane · never feeds Workflow Automation</text>
    <text class="pm-note" x="${PM_BUS + 4}" y="${340 + PM_TOP - 8}">≤ 4 engines per rule</text>`;
  return `<svg class="pm-svg" viewBox="0 0 ${PM_W_TOTAL} ${PM_H_TOTAL}" preserveAspectRatio="xMinYMin meet" role="img" aria-labelledby="pmTitle" aria-describedby="pmSummary" focusable="false">
    <title id="pmTitle">The DLP chain, end to end: content captured on a channel, dictionaries, engine, channel rule, then the evidence, telemetry and parallel lanes</title>
    <defs><marker id="pmArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="pm-arrow"/></marker></defs>
    ${cols}<g class="pm-edges">${edges}</g><g class="pm-cuts"></g>${never}<g class="pm-nodes">${nodes}</g><g class="pm-stops"></g><g class="pm-bits"></g>
  </svg>`;
}

// Draws the chain into `container` and returns { update(res), destroy() }.
function renderPathMotion(container) {
  container.innerHTML = `<div class="pm-head">
      <span class="pm-mode" id="pmMode">Reference chain</span>
      <span class="sep"></span>
      <button type="button" class="rp-btn" id="pmToggle" aria-controls="pmStage">Pause motion</button>
    </div>
    <div class="pm-wrap" id="pmStage">${_pmSvg()}</div>
    <div class="pm-legend" aria-hidden="true"><span><i class="lane-main"></i>content and verdict</span><span><i class="lane-ev"></i>evidence lane (feeds Workflow Automation)</span><span><i class="lane-tel"></i>telemetry and parallel paths (never feed it)</span><span><b class="pm-x">✕</b>where the chain breaks</span><span><b class="pm-sq">■</b>where policy blocks it</span><span><b class="pm-q">?</b>rules that could not be read</span><span><b class="pm-o">–</b>not in scope (not read)</span><span><i class="lane-assumed"></i>evidence path assumed, not confirmed (ICAP only)</span></div>
    <div class="df-hint" id="pmMotionNote"></div>
    <ul class="pm-summary" id="pmSummary"></ul>`;
  const svg = container.querySelector('.pm-svg');
  const bitsG = svg.querySelector('.pm-bits'), stopsG = svg.querySelector('.pm-stops'), cutsG = svg.querySelector('.pm-cuts');
  const btn = container.querySelector('#pmToggle'), note = container.querySelector('#pmMotionNote');
  const paths = {};
  svg.querySelectorAll('.pm-edge').forEach(p => { paths[p.dataset.edge] = p; });
  const lens = {};
  const lenOf = k => (lens[k] != null ? lens[k] : (lens[k] = paths[k].getTotalLength()));
  const reduce = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : { matches: false };
  const SPEED = 120, MAX_BITS = 90;
  let routes = [], bits = [], raf = 0, last = 0, chosen = null, onScreen = true, destroyed = false;

  function playing() { return chosen != null ? chosen : !reduce.matches; }
  function setNote() {
    // The label says what a press does, so no aria-pressed: a toggle whose
    // label also flips would be read as "Play motion, pressed" while paused.
    btn.textContent = playing() ? 'Pause motion' : 'Play motion';
    note.textContent = playing() ? 'Bits move along each lane; a ✕ marks where the chain breaks and a ■ where policy blocks the traffic; a ? marks rules that could not be read and a – a part not in scope on the Scope page (hover any of them, or read the list below).'
      : (reduce.matches && chosen == null ? 'Motion is off because your system asks for reduced motion: the arrows show each lane\'s direction. Play motion starts it anyway.'
        : 'Motion paused: the arrows show each lane\'s direction.');
  }
  function clearBits() { bits.forEach(b => b.el.remove()); bits = []; }
  function frame(ts) {
    const dt = last ? Math.min(0.05, (ts - last) / 1000) : 0;
    last = ts;
    routes.forEach(r => {
      r.acc += dt * r.rate;
      while (r.acc >= 1) {
        r.acc -= 1;
        if (bits.length >= MAX_BITS) continue;
        const el = document.createElementNS(PM_SVGNS, 'circle');
        el.setAttribute('r', '3.6');
        el.setAttribute('class', `pm-bit lane-${r.lane}${r.tone === 'assumed' ? ' assumed' : ''}`);
        bitsG.appendChild(el);
        bits.push({ r, d: 0, el, dead: false });
      }
    });
    bits = bits.filter(b => {
      if (b.dead) return true;
      b.d += SPEED * dt;
      const r = b.r;
      if (b.d >= r.end) {
        if (r.stop != null) {
          b.dead = true; b.el.classList.add('pop'); b.el.classList.add(`tone-${r.tone || 'broken'}`);
          setTimeout(() => { b.el.remove(); bits = bits.filter(x => x !== b); }, 450);
          return true;
        }
        b.el.remove();
        return false;
      }
      let d = b.d, i = 0;
      while (i < r.lens.length - 1 && d > r.lens[i]) { d -= r.lens[i]; i++; }
      const p = paths[r.edges[i]].getPointAtLength(d);
      b.el.setAttribute('cx', p.x.toFixed(1)); b.el.setAttribute('cy', p.y.toFixed(1));
      // The bit takes the colour of the lane it is on now.
      const lane = _pmLane(r.edges[i]);
      if (b.lane !== lane) { b.lane = lane; b.el.setAttribute('class', `pm-bit lane-${lane}${r.tone === 'assumed' ? ' assumed' : ''}`); }
      return true;
    });
    raf = requestAnimationFrame(frame);
  }
  function start() { if (!destroyed && !raf && playing() && onScreen && !document.hidden) { last = 0; raf = requestAnimationFrame(frame); } }
  function halt() { if (raf) cancelAnimationFrame(raf); raf = 0; }
  function sync() { setNote(); if (playing()) start(); else { halt(); clearBits(); } }

  function update(res) {
    const m = pmModel(res);
    halt(); clearBits(); stopsG.innerHTML = ''; cutsG.innerHTML = '';
    // Edge and node states: live up to each stop, the stopping edge
    // marked, everything no route reaches dimmed.
    const live = new Set(), cut = new Set(), reached = new Set(), cutNodes = new Set();
    m.routes.forEach(r => r.edges.forEach((e, i) => {
      const [a, b] = e.split('>');
      if (r.stop == null || i < r.stop) { live.add(e); reached.add(a); reached.add(b); } else if (i === r.stop) { cut.add(`${e}|${r.tone}`); reached.add(a); cutNodes.add(b); }
    }));
    Object.entries(paths).forEach(([k, p]) => {
      const c = [...cut].find(x => x.startsWith(`${k}|`));
      p.classList.toggle('is-off', !live.has(k) && !c);
      p.classList.toggle('is-broken', !!c && !live.has(k) && c.endsWith('|broken'));
      p.classList.toggle('is-blocked', !!c && !live.has(k) && c.endsWith('|blocked'));
      p.classList.toggle('is-unread', !!c && !live.has(k) && c.endsWith('|unread'));
      p.classList.toggle('is-scope', !!c && !live.has(k) && c.endsWith('|scope'));
      p.classList.toggle('is-assumed', !!(m.extra.assumed || []).includes(k));
    });
    // Dimmed edges first, live ones over them, the broken link on top:
    // edges share the forwarding bus, so paint order decides what shows.
    const edgesG = svg.querySelector('.pm-edges'), rank = p => (p.classList.contains('is-off') ? 0 : PM_CUT_CLS.some(c => p.classList.contains(c)) ? 2 : 1);
    Object.values(paths).sort((a, b) => rank(a) - rank(b)).forEach(p => edgesG.appendChild(p));
    // A broken or blocked edge that shares the bus with live ones shows its
    // mark only on its own stretch (_pmOwnD); the shared stretch keeps the
    // live lanes' look. The full path stays as the bits' geometry.
    const liveKeys = [...live];
    Object.entries(paths).forEach(([k, p]) => {
      const cutTone = PM_CUT_CLS.find(c => p.classList.contains(c)) || '';
      const own = cutTone ? _pmOwnD(k, liveKeys) : null, split = !!own && own !== _pmEdgeD(k);
      p.classList.toggle('is-split', split);
      p.setAttribute('marker-end', split ? 'none' : 'url(#pmArrow)');
      if (!split) return;
      const o = document.createElementNS(PM_SVGNS, 'path');
      o.setAttribute('class', `pm-edge pm-own lane-${_pmLane(k)} ${cutTone}`);
      o.setAttribute('data-own', k);
      o.setAttribute('d', own);
      o.setAttribute('marker-end', 'url(#pmArrow)');
      cutsG.appendChild(o);
    });
    svg.querySelectorAll('.pm-node').forEach(g => {
      const k = g.dataset.node;
      g.classList.toggle('is-off', !reached.has(k) && !cutNodes.has(k));
      g.classList.toggle('is-cut', cutNodes.has(k) && !reached.has(k));
      const tag = m.extra[k];
      g.classList.toggle('st-ok', tag === 'enforce'); g.classList.toggle('st-warn', tag === 'monitor');
      g.querySelector('.tag').textContent = tag === 'enforce' ? 'ENFORCE' : tag === 'monitor' ? 'MONITOR' : '';
    });
    m.stops.forEach(s => {
      const p = paths[s.edge], pt = p.getPointAtLength(_pmStopLen(s.edge, lenOf(s.edge)));
      const g = document.createElementNS(PM_SVGNS, 'g');
      g.setAttribute('class', `pm-stop tone-${s.tone}`);
      g.setAttribute('transform', `translate(${pt.x.toFixed(1)},${pt.y.toFixed(1)})`);
      g.innerHTML = `<title>${_pmE(s.reason)}</title><circle r="9"/><text y="4" text-anchor="middle">${PM_MARK[s.tone] || PM_MARK.broken}</text>`;
      stopsG.appendChild(g);
    });
    routes = m.routes.map(r => {
      const ls = r.edges.map(lenOf), total = ls.reduce((a, b) => a + b, 0);
      const end = r.stop == null ? total : ls.slice(0, r.stop).reduce((a, b) => a + b, 0) + _pmStopLen(r.edges[r.stop], ls[r.stop]);
      // Stagger the first bits so the lanes do not pulse in step.
      return Object.assign({}, r, { lens: ls, end, acc: Math.random(), lane: _pmLane(r.edges[0]) });
    });
    container.querySelector('#pmMode').textContent = m.mode === 'reference' ? 'Reference chain · every lane idling' : m.mode === 'live' ? 'This session · each lane carries the incidents it raised' : 'This path · bits stop where the chain breaks';
    container.querySelector('#pmSummary').innerHTML = m.summary.map(s => `<li>${_pmE(s)}</li>`).join('');
    sync();
    return m;
  }

  const onClick = () => { chosen = !playing(); sync(); };
  const onReduce = () => { if (chosen == null) sync(); };
  btn.addEventListener('click', onClick);
  if (reduce.addEventListener) reduce.addEventListener('change', onReduce);
  const onVis = () => { if (document.hidden) halt(); else start(); };
  document.addEventListener('visibilitychange', onVis);
  let io = null;
  if (window.IntersectionObserver) {
    io = new IntersectionObserver(es => { onScreen = es.some(e => e.isIntersecting); if (onScreen) start(); else halt(); });
    io.observe(svg);
  }
  update(null);
  return {
    update,
    // After destroy nothing may start the loop again: not the button, not a
    // reduced-motion change, not visibility or scrolling.
    destroy() {
      destroyed = true; halt(); clearBits();
      btn.removeEventListener('click', onClick);
      if (reduce.removeEventListener) reduce.removeEventListener('change', onReduce);
      document.removeEventListener('visibilitychange', onVis); if (io) io.disconnect();
    },
  };
}
window.renderPathMotion = renderPathMotion;
