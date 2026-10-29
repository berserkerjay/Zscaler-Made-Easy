// ── Flow animator: moving pictures of the flows the app analyses ─────
// One module, five pictures, all driven by results the app already
// produces (nothing here reads the tenant on its own):
//   - hop player: a Path analyzer result walked hop by hop (Client
//     Connector → forwarding → PAC → Cloud App Control → URL → SSL →
//     File Type Control → Web DLP → destination); the dot stops where
//     the traffic stops and everything after it greys out;
//   - DLP drill-down: inside DLP, content → dictionaries (match counts)
//     → engines (each term of the expression against its count) →
//     rules → action. An engine that does not fire says why: a near
//     miss ("3 found, needs more than 5") or nothing to match;
//   - deployment graph: a policy-pack plan (templates → dictionaries →
//     engines → rules) with content streaming along the edges and the
//     deploy order replayed from the results;
//   - live traffic: Workflow Automation DLP incidents as they land, each
//     one a dot through channel → dictionaries → engine → rule →
//     enforced or monitor-only → Workflow Automation;
//   - architecture flows: the Data Security Architect reference flows
//     (/reference/data-security-architect) as step-by-step animations,
//     with the gates people miss marked.
// The model builders (FA.pathModel, FA.corpusModel, FA.deployModel,
// FA.liveModel, FA.ARCH) are pure, so the tests run them under node.
// Rendering is inline SVG + requestAnimationFrame. Motion honours
// prefers-reduced-motion (final states drawn at once) and pauses while
// the tab is hidden. Every picture has a text alternative next to it.
(function (root) {
  'use strict';
  const SVGNS = 'http://www.w3.org/2000/svg';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const clip = (s, n) => { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
  const up = s => String(s == null ? '' : s).trim().toUpperCase();

  // ── Pure models ──────────────────────────────────────────────────
  const HOP_LABEL = {
    device: 'Device', zcc: 'App profile', forwarding: 'Forwarding', pac: 'PAC file', zia: 'ZIA',
    cac: 'Cloud App Control', url: 'URL filtering', ssl: 'SSL inspection', ftc: 'File Type Control',
    dlp: 'Web DLP', incident: 'Incident', dest: 'Destination',
  };
  const STATUS_WORD = {
    pass: 'passes', warn: 'weak point', bypass: 'bypassed', blocked: 'blocked', blind: 'not inspected',
    none: 'no rule', unknown: 'unknown', out_of_scope: 'not in scope', assumed: 'assumed', skipped: 'skipped',
    na: 'not applicable', enforce: 'enforcing', monitor: 'monitor only',
  };
  // A hop's tone: pass (green), warn (amber), stop (red: the traffic ends
  // here), idle (grey: nothing decided here, the traffic goes on).
  function hopTone(status) {
    if (status === 'blocked' || status === 'bypass') return 'stop';
    if (status === 'pass' || status === 'enforce') return 'pass';
    if (status === 'warn' || status === 'blind' || status === 'monitor' || status === 'assumed' || status === 'unknown') return 'warn';
    return 'idle';
  }
  const OUTCOME_TONE = { blocked: 'bad', bypassed: 'bad', blind: 'warn', monitor: 'warn', none: 'warn', unknown: 'warn', out_of_scope: 'warn', enforce: 'ok' };

  function destText(d) {
    if (!d) return '';
    if (typeof d === 'string') return d;
    return d.host || d.input || d.name || '';
  }

  // Path analyzer result → {hops, stop, verdict, dlp}.
  function pathModel(res) {
    if (!res || !res.trace) return null;
    const t = res.trace, v = res.verdict || {};
    const net = { off: 'off network', on: 'on trusted network', vpn: 'on VPN' }[res.network || t.network] || (res.network || t.network || '');
    const hops = [{ key: 'device', label: HOP_LABEL.device, sub: [res.platform || t.platform, net].filter(Boolean).join(' · '), tone: 'pass', status: 'pass', note: 'The user\'s device starts the transaction.' }];
    let dlp = null;
    (t.hops || []).forEach(h => {
      if (!h || (h.key === 'zia' && h.status === 'skipped')) return;
      const by = h.decided_by && h.decided_by.name;
      const wp = h.weak_point;
      hops.push({
        key: h.key, label: h.label || HOP_LABEL[h.key] || h.key, status: h.status,
        sub: clip(by || STATUS_WORD[h.status] || h.status || '', 26), tone: hopTone(h.status),
        note: [h.detail, wp && wp.title ? `Weak point: ${wp.title}` : '', wp && wp.fix ? `Fix: ${wp.fix}` : ''].filter(Boolean).join(' '),
        by: by || '',
      });
      if (h.key === 'dlp') {
        dlp = { rules: (h.rules || []).map(r => ({ id: r.id, channel: r.channel, name: r.name, action: r.action || (r.enforcing ? 'BLOCK' : 'ALLOW'), enforcing: !!r.enforcing, engines: (r.engines || []).map(String), engine_ids: (r.engine_ids || []).map(String) })) };
      }
    });
    let stop = -1;
    for (let i = 0; i < hops.length; i++) if (hops[i].tone === 'stop') { stop = i; break; }
    const dest = destText(res.destination) || destText(t.destination);
    hops.push({ key: 'dest', label: HOP_LABEL.dest, sub: clip(dest, 26), tone: stop >= 0 ? 'after' : (t.decrypted === false ? 'warn' : 'pass'), status: 'dest',
      note: stop >= 0 ? 'Never reached.' : (t.decrypted === false ? 'Reached without content inspection.' : 'Reached.') });
    if (stop >= 0) for (let i = stop + 1; i < hops.length; i++) hops[i].tone = 'after';
    const outcome = v.outcome || t.outcome || '';
    return {
      hops, stop, dlp, dest, context: res.context || res.scenario || null,
      verdict: { tone: OUTCOME_TONE[outcome] || 'warn', outcome, text: [v.headline, v.summary].filter(Boolean).join(' ') || outcome },
    };
  }

  // One term of an engine expression, as corpus_engines explains it:
  //   "D63.S > 1: 3 → true", "Sum(D1.S + D2.S) > 6: 7 → true",
  //   "D9.S > 0: unknown (not simulated)".
  const TERM_RE = /^\s*(?:Sum\(([^)]*)\)|D(\d+)\.S)\s*(>=|<=|!=|==|>|<|=)\s*(\d+)\s*:\s*(.*)$/;
  function parseTerm(text) {
    const m = TERM_RE.exec(String(text || ''));
    if (!m) return { text: String(text || ''), ids: [], op: '', n: null, count: null, ok: null };
    const ids = m[1] ? (m[1].match(/D(\d+)/g) || []).map(x => x.slice(1)) : [m[2]];
    const r = /^(\d+)\s*→\s*(true|false)/.exec(m[5]);
    return { text: String(text), ids, sum: !!m[1], op: m[3], n: Number(m[4]), count: r ? Number(r[1]) : null, ok: r ? r[2] === 'true' : null };
  }
  const OP_WORD = { '>': 'more than', '>=': 'at least', '<': 'fewer than', '<=': 'at most', '=': 'exactly', '==': 'exactly', '!=': 'not' };

  function engineWhy(fires, terms, expression) {
    const simple = /^\s*\(?\s*(?:D\d+\.S|Sum\([^()]*\))\s*(?:>=|<=|!=|==|>|<|=)\s*\d+\s*\)?\s*$/.test(expression || '');
    if (fires === true) {
      const t = terms.filter(x => x.ok === true && x.count !== null)[0];
      return { kind: 'fires', text: t && simple ? `fires: ${t.count} found, needs ${OP_WORD[t.op] || t.op} ${t.n}` : 'engine expression is satisfied' };
    }
    if (fires === null) return { kind: 'unknown', text: 'unknown: a dictionary it uses cannot be simulated here' };
    const near = terms.filter(x => x.ok === false && x.count > 0)[0];
    if (near && simple) return { kind: 'near', text: `near miss: ${near.count} found, needs ${OP_WORD[near.op] || near.op} ${near.n}` };
    return { kind: 'none', text: 'engine expression is not satisfied' };
  }

  // The engines a picture can hold: firing ones and near misses first.
  const ENGINE_MAX = 6, RULE_MAX = 6, DICT_MAX = 7;
  const WHY_RANK = { fires: 0, near: 1, unknown: 2, none: 3, unmeasured: 4 };

  // Local corpus test result (/api/dlp/efficacy/test) → drill model.
  function corpusModel(res, opts) {
    if (!res || !Array.isArray(res.engines)) return null;
    const o = opts || {};
    const byId = {};
    (res.results || []).forEach(d => { byId[String(d.id)] = { key: 'd' + d.id, name: d.name, count: d.total_hits == null || d.simulated === false ? null : Number(d.total_hits) || 0 }; });
    (res.predefined || []).forEach(d => {
      const c = d.simulated ? Number(d.total_hits != null ? d.total_hits : d.hits) || 0 : null;
      byId[String(d.id)] = { key: 'd' + d.id, name: d.name, count: c };
    });
    const actions = {};
    (o.rules || []).forEach(r => { if (r.id != null) actions[String(r.channel || o.channel || '') + ':' + String(r.id)] = r; });
    let engines = res.engines.map(e => {
      const terms = (e.terms || []).map(parseTerm);
      const why = engineWhy(e.fires === undefined ? null : e.fires, terms, e.expression);
      if (e.explanation) why.text = String(e.explanation);
      return { id: e.id, name: e.name, rule_objects: e.rule_objects || [], expr: e.expression || '', fires: e.fires === undefined ? null : e.fires, terms, why, rules: (e.rules || []).slice() };
    });
    const total = engines.length;
    engines.sort((a, b) => (WHY_RANK[a.why.kind] - WHY_RANK[b.why.kind]) || String(a.name).localeCompare(String(b.name)));
    engines = engines.slice(0, ENGINE_MAX);
    const dictKeys = [], dicts = [];
    engines.forEach(e => {
      e.dicts = [];
      e.terms.forEach(t => t.ids.forEach(id => {
        const d = byId[id] || { key: 'd' + id, name: 'D' + id, count: t.sum ? null : t.count };
        if (dictKeys.indexOf(d.key) < 0) { dictKeys.push(d.key); dicts.push(d); }
        if (e.dicts.indexOf(d.key) < 0) e.dicts.push(d.key);
      }));
    });
    const rules = [];
    engines.forEach((e, i) => {
      const refs = e.rule_objects.length ? e.rule_objects : e.rules.map(name => ({ name }));
      refs.forEach(ref => {
        const id = ref.id != null ? String(ref.id) : null;
        let r = id ? rules.find(x => x.id === id && x.channel === ref.channel) : null;
        if (!r) {
          const known = id && actions[String(ref.channel || o.channel || '') + ':' + id] || ref;
          r = { id, channel: ref.channel || known.channel || '', name: ref.name || known.name || 'Unnamed rule', engines: [],
            action: known.action || null, state: known.state || '', applicability: known.applicability || 'conditional' };
          rules.push(r);
        }
        r.engines.push(i);
      });
    });
    return {
      context: o.context || res.context || null,
      source: { label: o.label || 'Sample content', sub: o.sub || (res.corpus_length ? `${res.corpus_length} characters` : '') },
      dicts: dicts.slice(0, DICT_MAX), engines, rules: rules.slice(0, RULE_MAX),
      hidden: { engines: total - engines.length, dicts: Math.max(0, dicts.length - DICT_MAX), rules: Math.max(0, rules.length - RULE_MAX) },
      measured: o.measured !== false && res.mode !== 'configuration', incomplete: (res.errors || []).length > 0 || Object.values(res.read_evidence || {}).some(e => e.status === 'unverified'), totals: { fires: res.engines.filter(e => e.fires === true).length, unknown: res.engines.filter(e => e.fires == null).length, engines: res.engines.length }, note: res.note || '',
    };
  }

  // The DLP hop of a Path analyzer result → drill model without match
  // counts (the analyzer reads configuration, not content). A corpus
  // model, when one exists, fills in the counts for engines it knows.
  function pathDrillModel(path, corpus) {
    const a = path && path.context, b = corpus && corpus.context;
    const joined = a && b && ['tenant_key', 'scope_key', 'configuration_id'].every(k => a[k] && a[k] === b[k]) && (a.scenario_id || a.id) && (a.scenario_id || a.id) === (b.scenario_id || b.id);
    if (!joined) corpus = null;
    if (!path || !path.dlp || !path.dlp.rules.length) return corpus || null;
    const known = {};
    if (corpus) corpus.engines.forEach(e => { if (e.id != null) known[String(e.id)] = e; });
    const engines = [], rules = [];
    path.dlp.rules.slice(0, RULE_MAX).forEach(r => {
      const rule = { id: r.id, channel: r.channel, name: r.name, action: r.action, engines: [] };
      r.engines.forEach((n, position) => {
        let i = -1;
        const requestedId = (r.engine_ids || [])[position];
        for (let k = 0; k < engines.length; k++) if (requestedId != null ? String(engines[k].id) === String(requestedId) : engines[k].id == null && up(engines[k].name) === up(n)) i = k;
        if (i < 0 && engines.length < ENGINE_MAX) {
          const c = (r.engine_ids || [])[position] != null ? known[String(r.engine_ids[position])] : null;
          engines.push(c ? Object.assign({}, c, { rules: [] }) : { id: requestedId, name: n, expr: '', fires: null, terms: [], dicts: [], rules: [], why: { kind: 'unmeasured', text: 'not measured: run sample content in DLP decision' } });
          i = engines.length - 1;
        }
        if (i >= 0) rule.engines.push(i);
      });
      rules.push(rule);
    });
    const dicts = [];
    if (corpus) engines.forEach(e => (e.dicts || []).forEach(k => {
      const d = corpus.dicts.filter(x => x.key === k)[0];
      if (d && dicts.indexOf(d) < 0) dicts.push(d);
    }));
    return {
      source: { label: 'Content on this path', sub: path.dest || '' }, dicts: dicts.slice(0, DICT_MAX), engines, rules,
      hidden: { engines: 0, dicts: 0, rules: Math.max(0, path.dlp.rules.length - RULE_MAX) }, measured: !!corpus && engines.some(e => e.why.kind !== 'unmeasured'),
    };
  }

  // Deploy Studio plan payload ({items, results, stage}) → graph model.
  const DEPLOY_COLS = ['template', 'dictionary', 'engine', 'app_group', 'policy', 'resource'];
  const DEPLOY_COL_LABEL = { template: 'Templates', dictionary: 'Dictionaries', engine: 'Engines', app_group: 'App groups', policy: 'Rules', resource: 'Tenant prerequisites' };
  const DEPLOY_TONE = {
    created: 'pass', modified: 'pass', restored: 'pass', deleted: 'pass', gone: 'pass',
    reused: 'reuse', reuse: 'reuse', tenant: 'reuse', noop: 'reuse', keep: 'reuse', reuse_differs: 'warn',
    failed: 'stop', conflict: 'stop', blocked_dependency: 'stop', missing: 'stop', still_present: 'stop',
    skipped: 'idle', skip_empty: 'idle',
    create: 'plan', modify: 'plan', restore: 'plan', remove: 'plan',
  };
  const COL_MAX = 12;
  function depKey(s) {
    const i = String(s).indexOf(':');
    if (i < 0) return null;
    let kind = s.slice(0, i); const name = s.slice(i + 1);
    if (kind === 'predefined') kind = 'template';
    if (kind === 'missing') kind = 'resource';
    return kind + ':' + name;
  }
  function deployModel(p) {
    if (!p || !Array.isArray(p.items)) return null;
    const res = {};
    (p.results || []).forEach(r => { if (r && r.kind && r.name) res[r.kind + ':' + r.name] = r; });
    const nodes = {}, order = [];
    function add(key, extra) {
      if (nodes[key]) return nodes[key];
      const kind = key.slice(0, key.indexOf(':'));
      const n = Object.assign({ key, kind, name: key.slice(key.indexOf(':') + 1), status: kind === 'template' ? 'tenant' : (kind === 'resource' ? 'missing' : 'create') }, extra || {});
      nodes[key] = n; order.push(key); return n;
    }
    const edges = [];
    p.items.forEach(it => {
      const kind = it.kind === 'tweak' ? 'dictionary' : it.kind;
      const key = kind + ':' + it.name;
      const r = res[it.kind + ':' + it.name];
      add(key, { status: r ? r.status : it.status, planned: it.status, reason: it.reason || '', error: r ? (r.explanation || r.error || '') : '' });
      nodes[key].status = r ? r.status : it.status;
      (it.depends_on || []).forEach(d => {
        const k = depKey(d); if (!k) return;
        add(k);
        if (k.indexOf('resource:') === 0) edges.push({ from: key, to: k }); else edges.push({ from: k, to: key });
      });
    });
    const cols = DEPLOY_COLS.map(c => ({ kind: c, label: DEPLOY_COL_LABEL[c], keys: order.filter(k => nodes[k].kind === c) })).filter(c => c.keys.length);
    // Columns longer than COL_MAX fold the rest into one "+N more" node.
    const alias = {};
    cols.forEach(c => {
      if (c.keys.length <= COL_MAX) return;
      const more = c.kind + ':__more';
      nodes[more] = { key: more, kind: c.kind, name: `+${c.keys.length - (COL_MAX - 1)} more`, status: 'more', more: true };
      c.keys.slice(COL_MAX - 1).forEach(k => { alias[k] = more; });
      c.keys = c.keys.slice(0, COL_MAX - 1).concat([more]);
    });
    const seen = {};
    const outEdges = [];
    edges.forEach(e => {
      const a = alias[e.from] || e.from, b = alias[e.to] || e.to, k = a + '>' + b;
      if (a === b || seen[k] || !nodes[a] || !nodes[b]) return;
      seen[k] = 1; outEdges.push({ from: a, to: b });
    });
    Object.keys(nodes).forEach(k => { nodes[k].tone = nodes[k].more ? 'idle' : (DEPLOY_TONE[nodes[k].status] || 'plan'); });
    const counts = {};
    p.items.forEach(it => { const s = (res[it.kind + ':' + it.name] || {}).status || it.status; counts[s] = (counts[s] || 0) + 1; });
    return { cols, nodes, edges: outEdges, stage: p.stage || (p.results ? 'deployed' : 'plan'), counts, tenant: p.tenant_label || '', packs: p.packs || [], at: p.at || null };
  }

  // One Workflow Automation incident (Live DLP feed) → the lanes it took.
  // Only what the picture needs: no user names, no file names.
  const LIVE_CHANNELS = ['web', 'endpoint', 'email', 'saas', 'unknown'];
  function liveModel(inc) {
    if (!inc) return null;
    const ch = LIVE_CHANNELS.indexOf(inc.channel) >= 0 ? inc.channel : 'unknown';
    const dicts = (inc.dictionaries || []).map(d => ({ name: d.name, count: typeof d.count === 'number' && Number.isFinite(d.count) ? d.count : null })).sort((a, b) => b.count - a.count);
    return {
      id: String(inc.id || ''), channel: ch, at: inc.created_at || '',
      controls: ['URL Filtering', 'SSL Inspection', 'File Type Control'].map(label => ({ label, status: ch === 'web' || ch === 'unknown' ? 'unverified' : 'not_applicable', reason: ch === 'web' || ch === 'unknown' ? 'Not present in the incident feed; no upstream decision observed.' : 'Inline web control is not an enforcement hop of this channel.' })),
      rule: (inc.rules || [])[0] || '', engine: (inc.engines || [])[0] || '', dicts,
      enforcement: inc.enforcement === 'enforced' ? 'enforced' : (inc.enforcement === 'monitor' ? 'monitor' : 'unknown'),
      dest: inc.host || inc.destination || inc.application || '', severity: inc.severity || '',
    };
  }

  // ── Data Security Architect flows ────────────────────────────────
  // From /reference/data-security-architect, in its own order. `gate`
  // marks the step the reference calls out as the one people miss.
  const ARCH = [
    { id: 'chain', title: 'The chain, end to end', anchor: 'chain', steps: [
      { t: 'Content captured', s: 'Any channel: inline web, endpoint, email, SaaS API.' },
      { t: 'Dictionaries', s: 'Each reports a match count, never a verdict.' },
      { t: 'Engine', s: 'Boolean of dictionaries, strict "more than N" per dictionary; the Channels gate decides which rules can see it.' },
      { t: 'Channel rule acts', s: 'Block, allow, quarantine or confirm, plus notifications; at most four engines per rule.' },
      { t: 'Evidence forwarded', s: 'Incident Receiver or cloud-to-cloud, set on each rule. Not set: Workflow Automation stays empty.', gate: true },
      { t: 'Customer storage', s: 'The -data and -metadata buckets.' },
      { t: 'Storage event', s: 'Tells the integration a new incident landed.' },
      { t: 'Workflow Automation', s: 'Reads the metadata only. NSS → SIEM telemetry, auditor email and ICAP never feed it.' },
    ] },
    { id: 'dictionaries', title: '01 Dictionaries', anchor: 'dictionaries', steps: [
      { t: 'Pick the type', s: 'Predefined first; Patterns & Phrases for a new shape; EDM for your records; IDM for your documents; MIP labels.' },
      { t: 'OCR gate', s: 'Text in images is only seen when OCR is on.', gate: true },
      { t: 'Pattern / phrase scan', s: 'Regex and phrases run over the extracted text.' },
      { t: 'Match type and proximity', s: 'Exact or partial; proximity narrows what counts.' },
      { t: 'Count', s: 'The dictionary hands a match count to the engine.' },
      { t: 'Engine threshold', s: 'Strictly more than N: "> 1" needs 2 matches.' },
    ] },
    { id: 'engines', title: '02 Engines', anchor: 'engines', steps: [
      { t: 'Builder tree', s: 'Root All / Any / Sum (Exclude cannot be the root); ≤ 4 subexpressions per level, ≤ 16 dictionaries per operator.' },
      { t: 'Strict counts', s: 'Each dictionary term is "more than N"; Sum adds counts across dictionaries.' },
      { t: 'Verdict', s: 'True or false for this content.' },
      { t: 'Channels gate', s: 'Only channels ticked on the engine can use it in a rule.', gate: true },
      { t: 'Rule', s: 'At most four engines per rule.' },
    ] },
    { id: 'inline', title: '03 Inline web DLP', anchor: 'inline', overlay: true, steps: [
      { t: 'Capture', s: 'Client Connector tunnel or PAC brings the traffic to ZIA.', hop: ['zcc', 'forwarding', 'pac'] },
      { t: 'Decrypt', s: 'SSL inspection; Do Not Inspect stays encrypted and DLP sees nothing.', gate: true, hop: ['ssl'] },
      { t: 'Cloud App Control', s: 'A block here means DLP never runs.', hop: ['cac'] },
      { t: 'URL filtering', s: 'A block here means DLP never runs.', hop: ['url'] },
      { t: 'Threat checks', s: 'Malware, sandbox, ATP.' },
      { t: 'File Type Control', s: 'Bulk formats can be stopped before content inspection.', hop: ['ftc'] },
      { t: 'Content inspection', s: 'Text extracted, dictionaries counted, engines evaluated.', hop: ['dlp'] },
      { t: 'Rule action', s: 'First matching rule (or the most restrictive with Evaluate All) acts.' },
      { t: 'Log and evidence', s: 'Web logs to NSS; evidence to the Incident Receiver or cloud-to-cloud.', hop: ['incident'] },
    ] },
    { id: 'endpoint', title: '04 Endpoint DLP', anchor: 'endpoint', steps: [
      { t: 'Content pushed', s: 'Dictionaries and engines built in the cloud, pushed to the device.' },
      { t: 'Activity intercepted', s: 'Device Control acts at plug-in, before Endpoint DLP rules.' },
      { t: 'All rules evaluated', s: 'Every rule, not first match.' },
      { t: 'Inspected on device', s: 'Content never leaves for inspection.' },
      { t: 'Most restrictive wins', s: 'Block beats confirm beats allow.' },
      { t: 'Notify the user', s: 'The endpoint notification template.' },
      { t: 'Log locally', s: 'Then uploaded with the evidence.' },
      { t: 'Evidence / incident', s: 'The same evidence chain as every other channel.', gate: true },
    ] },
    { id: 'email', title: '05 Email DLP', anchor: 'email', steps: [
      { t: 'Outbound mailbox', s: 'Exchange Online, Gmail or a gateway.' },
      { t: 'Redirect to Zscaler', s: 'Smart host connector with the tenant identity header.' },
      { t: 'Rules per recipient', s: 'Evaluated for each recipient.' },
      { t: 'Most restrictive', s: 'One verdict per recipient.' },
      { t: 'Verdict headers', s: 'Zscaler tags; it does not block.' },
      { t: 'Platform enforces', s: 'A transport rule on the headers. Without it, silent monitor-only.', gate: true },
      { t: 'Loop prevention', s: 'Without it, inspected mail is sent back to Zscaler forever.', gate: true },
      { t: 'Log and evidence', s: 'Email logs and incidents.' },
    ] },
    { id: 'saas', title: '06 SaaS Security API', anchor: 'saas', steps: [
      { t: 'Tenant onboarded', s: 'The sanctioned SaaS tenant is connected.' },
      { t: 'Policy rules', s: 'SaaS DLP rules with engines.' },
      { t: 'Scan configuration', s: 'Must exist, reference at least one policy, and be started by hand, or nothing scans.', gate: true },
      { t: 'Crawl at rest', s: 'Out of band, nothing inline. Watch the cutoff date.' },
      { t: 'Verdict per file', s: 'Each file evaluated.' },
      { t: 'Remediation', s: 'Quarantine, remove sharing, label, per application.' },
      { t: 'Forwarding', s: 'Evidence to Workflow Automation.' },
    ] },
    { id: 'edmidm', title: '07 EDM and IDM', anchor: 'edmidm', steps: [
      { t: 'Index Tool VM', s: 'Customer-hosted; raw data stays on premises.', gate: true },
      { t: 'Hashes / fingerprints', s: 'Only hashes leave.' },
      { t: 'Template completed', s: 'The dictionary type cannot be created before this.' },
      { t: 'EDM / IDM dictionary', s: 'Fires only on your records or documents.' },
      { t: 'Engine and Channels gate', s: 'Decides which channels can use it.' },
      { t: 'Inline, SaaS, email', s: 'Endpoint has its own rules for EDM/IDM.' },
    ] },
    { id: 'aisec', title: '08 AI security', anchor: 'aisec', steps: [
      { t: 'Client Connector', s: 'The user reaches an AI app.' },
      { t: 'Inline gauntlet', s: 'The same ZIA stack as web.' },
      { t: 'Forwarding Control', s: 'Proxy-chains AI domains to AI Guard.', gate: true },
      { t: 'AI Guard policy', s: 'Which detectors run.' },
      { t: 'Prompt detectors', s: 'Before the prompt reaches the model.' },
      { t: 'LLM', s: 'The model answers.' },
      { t: 'Response detectors', s: 'Before the answer reaches the user.' },
      { t: 'User', s: 'Gets the answer, or the block.' },
    ] },
    { id: 'workflow', title: '09 Workflow Automation', anchor: 'workflow', steps: [
      { t: 'Rule forwards evidence', s: 'Cloud-to-cloud, a ZIR VM in your cloud, or on-prem (no Workflow Automation).', gate: true },
      { t: 'Customer storage', s: 'The bucket the integration was validated against.' },
      { t: 'Storage event', s: 'Raised for each new object.' },
      { t: 'DLP Application Integration', s: 'Must show Enabled, not Failed.' },
      { t: 'Incident received', s: 'Metadata read; evidence stays in your storage.' },
      { t: 'Workflow', s: 'Triage, notify, escalate.' },
      { t: 'Resolved', s: 'With a resolution, which feeds the FP:TP ratio.' },
    ] },
  ];

  // ── Rendering helpers ────────────────────────────────────────────
  function reduced() { try { return root.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; } }
  function svgEl(tag, attrs, parent) {
    const el = root.document.createElementNS(SVGNS, tag);
    Object.keys(attrs || {}).forEach(k => el.setAttribute(k, attrs[k]));
    if (parent) parent.appendChild(el);
    return el;
  }
  function newSvg(host, w, h, label) {
    const s = svgEl('svg', { viewBox: `0 0 ${w} ${h}`, role: 'img', 'aria-label': label, class: 'fa-svg', tabindex: '0', focusable: 'true' });
    host.appendChild(s);
    return s;
  }
  function box(svg, x, y, w, h, title, sub, cls) {
    const g = svgEl('g', { class: 'fa-box' + (cls ? ' ' + cls : ''), transform: `translate(${x},${y})` }, svg);
    svgEl('rect', { width: w, height: h, rx: 8 }, g);
    const t1 = svgEl('text', { x: 10, y: sub ? 19 : h / 2 + 4, class: 'fa-t' }, g); t1.textContent = clip(title, Math.floor(w / 7));
    const t2 = svgEl('text', { x: 10, y: 35, class: 'fa-s' }, g); t2.textContent = clip(sub || '', Math.floor(w / 6.2));
    const tt = svgEl('title', {}, g); tt.textContent = title + (sub ? ' — ' + sub : '');
    return { g, t1, t2, x, y, w, h, set(cls2) { g.setAttribute('class', 'fa-box' + (cls2 ? ' ' + cls2 : '')); }, sub(s) { t1.setAttribute('y', s ? 19 : h / 2 + 4); t2.textContent = clip(s, Math.floor(w / 6.2)); } };
  }
  function curve(svg, a, b, cls) {
    const x1 = a.x + a.w, y1 = a.y + a.h / 2, x2 = b.x, y2 = b.y + b.h / 2, m = (x1 + x2) / 2;
    return svgEl('path', { d: `M${x1} ${y1} C${m} ${y1} ${m} ${y2} ${x2} ${y2}`, class: 'fa-edge' + (cls ? ' ' + cls : '') }, svg);
  }
  // A clock that stops while the tab is hidden and on destroy.
  function animator() {
    const jobs = new Set(); let raf = 0, dead = false;
    function frame(now) { raf = 0; if (dead) return; jobs.forEach(j => j(now)); if (jobs.size && !root.document.hidden) raf = root.requestAnimationFrame(frame); }
    function kick() { if (!raf && !dead && jobs.size && !root.document.hidden) raf = root.requestAnimationFrame(frame); }
    const vis = () => kick();
    root.document.addEventListener('visibilitychange', vis);
    return {
      add(j) { jobs.add(j); kick(); return () => jobs.delete(j); },
      clear() { jobs.clear(); if (raf) root.cancelAnimationFrame(raf); raf = 0; },
      destroy() { dead = true; jobs.clear(); if (raf) root.cancelAnimationFrame(raf); root.document.removeEventListener('visibilitychange', vis); },
    };
  }
  // Fly one dot along a path; resolves when it arrives (at once when
  // motion is reduced).
  function fly(clock, svg, path, ms, cls) {
    return new Promise(done => {
      if (reduced() || !path.getTotalLength) { done(); return; }
      const L = path.getTotalLength();
      const dot = svgEl('circle', { r: 5, class: 'fa-dot' + (cls ? ' ' + cls : '') }, svg);
      let t0 = null;
      const stop = clock.add(now => {
        if (t0 === null) t0 = now;
        const k = Math.min(1, (now - t0) / ms), p = path.getPointAtLength(L * k);
        dot.setAttribute('cx', p.x); dot.setAttribute('cy', p.y);
        if (k >= 1) { stop(); dot.remove(); done(); }
      });
    });
  }
  const wait = ms => new Promise(r => setTimeout(r, reduced() ? 0 : ms));

  // ── Hop player ───────────────────────────────────────────────────
  // model: pathModel(); opts.onHop(hop, i) after each hop lands;
  // opts.beforeLand(hop) → Promise (the DLP drill-down plugs in here).
  function hopPlayer(host, model, opts) {
    const o = opts || {};
    host.innerHTML = '';
    const clock = animator();
    const per = 5, BW = 150, BH = 46, W = 1000, GAP = (W - 20 - per * BW) / (per - 1), ROWH = 96;
    const n = model.hops.length, rows = Math.ceil(n / per);
    const svg = newSvg(host, W, rows * ROWH + 4, `Path of the traffic to ${model.dest || 'the destination'}, hop by hop`);
    const pos = model.hops.map((h, i) => {
      const r = Math.floor(i / per), c = i % per, col = r % 2 ? per - 1 - c : c;
      return { x: 10 + col * (BW + GAP), y: 8 + r * ROWH, w: BW, h: BH, r };
    });
    const edges = [];
    for (let i = 0; i < n - 1; i++) {
      const a = pos[i], b = pos[i + 1];
      let d;
      if (a.r !== b.r) d = `M${a.x + BW / 2} ${a.y + BH} L${b.x + BW / 2} ${b.y}`;
      else if (a.r % 2 === 0) d = `M${a.x + BW} ${a.y + BH / 2} L${b.x} ${b.y + BH / 2}`;
      else d = `M${a.x} ${a.y + BH / 2} L${b.x + BW} ${b.y + BH / 2}`;
      edges.push(svgEl('path', { d, class: 'fa-edge' }, svg));
    }
    const boxes = model.hops.map((h, i) => box(svg, pos[i].x, pos[i].y, BW, BH, h.label, h.sub));
    let i = 0, busy = false, done = false, auto = false, gen = 0;
    function reset() {
      gen++; i = 0; busy = false; done = false; auto = false;
      clock.clear(); svg.querySelectorAll('.fa-dot').forEach(dot => dot.remove());
      boxes.forEach(b => b.set('')); edges.forEach(e => e.setAttribute('class', 'fa-edge'));
      boxes[0].set(model.hops[0].tone || 'idle');
      if (o.onReset) o.onReset();
    }
    function finish() {
      done = true;
      if (model.stop >= 0) {
        for (let k = model.stop; k < edges.length; k++) edges[k].setAttribute('class', 'fa-edge dead');
        for (let k = model.stop + 1; k < boxes.length; k++) boxes[k].set('after');
      }
      if (o.onDone) o.onDone();
    }
    async function step() {
      if (busy || done) return;
      if (model.stop === 0) { finish(); return; }
      const my = gen;
      if (i >= n - 1) { finish(); return; }
      busy = true;
      const hop = model.hops[i + 1];
      edges[i].setAttribute('class', 'fa-edge lit'); boxes[i + 1].set('on');
      await fly(clock, svg, edges[i], o.slow && o.slow() ? 1300 : 600);
      if (my !== gen) return;
      if (o.beforeLand) await o.beforeLand(hop);
      if (my !== gen) return;
      boxes[i + 1].set(hop.tone === 'after' ? 'after' : hop.tone);
      i++; busy = false;
      if (o.onHop) o.onHop(hop, i);
      if (hop.tone === 'stop' || i >= n - 1) { finish(); return; }
      if (auto) setTimeout(() => { if (my === gen) step(); }, o.slow && o.slow() ? 450 : 160);
    }
    reset();
    return {
      play() { reset(); auto = true; if (model.stop === 0) { finish(); return; } if (reduced()) { while (!done && i < n - 1) { const h = model.hops[i + 1]; edges[i].setAttribute('class', 'fa-edge lit'); boxes[i + 1].set(h.tone); i++; if (o.onHop) o.onHop(h, i); if (h.tone === 'stop') break; } if (o.beforeLand && model.hops.slice(0, i + 1).some(h => h.key === 'dlp')) o.beforeLand(model.hops.filter(h => h.key === 'dlp')[0]); finish(); return; } step(); },
      step() { auto = false; if (done) return; step(); },
      reset, destroy() { gen++; clock.destroy(); host.innerHTML = ''; },
    };
  }

  // ── DLP drill-down ───────────────────────────────────────────────
  function drill(host, model) {
    host.innerHTML = '';
    const clock = animator();
    const rowsN = Math.max(model.dicts.length, model.engines.length, model.rules.length, 1);
    const RH = 70, H = Math.max(rowsN * RH + 20, 130);
    const svg = newSvg(host, 1000, H, 'Inside DLP: content, dictionaries with match counts, engines, rules');
    const col = (i, len) => 14 + i * RH + (rowsN - len) * RH / 2;
    const src = box(svg, 8, H / 2 - 23, 150, 46, model.source.label, model.source.sub);
    const D = model.dicts.map((d, i) => box(svg, 220, col(i, model.dicts.length), 200, 46, d.name, model.measured ? 'scanning…' : 'not tested'));
    const G = model.engines.map((e, i) => box(svg, 490, col(i, model.engines.length), 210, 46, e.name, e.terms.length ? e.terms.map(t => `${t.sum ? 'Sum' : 'D'} ${t.op} ${t.n}`).join(', ') : (e.expr || '')));
    const R = model.rules.map((r, i) => box(svg, 775, col(i, model.rules.length), 215, 46, r.name, r.action || ''));
    const dIdx = {}; model.dicts.forEach((d, i) => { dIdx[d.key] = i; });
    const sd = D.map(b => curve(svg, src, b));
    const de = []; model.engines.forEach((e, i) => (e.dicts || []).forEach(k => { if (dIdx[k] !== undefined) de.push({ e: i, d: k, p: curve(svg, D[dIdx[k]], G[i]) }); }));
    const srcToEngine = model.dicts.length ? [] : G.map(g => curve(svg, src, g));
    const er = []; model.rules.forEach((r, i) => r.engines.forEach(e => { if (G[e]) er.push({ r: i, e, p: curve(svg, G[e], R[i]) }); }));
    const whyText = [];
    let gen = 0;
    async function play() {
      const my = ++gen;
      src.set('on'); D.forEach(b => { b.set(''); b.sub('scanning…'); }); G.forEach(b => b.set('')); R.forEach(b => b.set(''));
      sd.concat(srcToEngine).concat(de.map(x => x.p)).concat(er.map(x => x.p)).forEach(p => p.setAttribute('class', 'fa-edge'));
      whyText.forEach(t => t.remove()); whyText.length = 0;
      await wait(200);
      await Promise.all(D.map((b, i) => {
        sd[i].setAttribute('class', 'fa-edge lit');
        return fly(clock, svg, sd[i], 650).then(() => {
          if (my !== gen) return;
          const c = model.dicts[i].count;
          b.sub(c === null ? 'not simulated' : `${c} match${c === 1 ? '' : 'es'}`);
          b.set(c ? 'pass' : (c === null ? 'warn' : 'after'));
        });
      }));
      srcToEngine.forEach(p => p.setAttribute('class', 'fa-edge lit'));
      if (my !== gen) return;
      await wait(250);
      const fired = [];
      for (let i = 0; i < G.length; i++) {
        if (my !== gen) return;
        const e = model.engines[i], k = e.why.kind;
        G[i].set('on');
        const ins = de.filter(x => x.e === i);
        const live = ins.filter(x => { const d = model.dicts[dIdx[x.d]]; return d && d.count; });
        live.forEach(x => x.p.setAttribute('class', 'fa-edge lit'));
        if (live.length) await Promise.all(live.map(x => fly(clock, svg, x.p, 600)));
        else if (srcToEngine[i]) await fly(clock, svg, srcToEngine[i], 500);
        const tone = k === 'fires' ? 'pass' : k === 'near' ? 'stop' : k === 'unknown' || k === 'unmeasured' ? 'warn' : 'after';
        G[i].set(tone);
        if (k !== 'fires') ins.forEach(x => x.p.setAttribute('class', 'fa-edge' + (k === 'near' ? ' dead' : '')));
        const w = svgEl('text', { x: G[i].x, y: G[i].y + G[i].h + 13, class: 'fa-why ' + k }, svg);
        w.textContent = (k === 'fires' ? '✓ ' : k === 'near' ? '✗ ' : '– ') + clip(e.why.text, 46);
        whyText.push(w);
        fired[i] = k === 'fires';
        await wait(300);
      }
      for (let i = 0; i < R.length; i++) {
        if (my !== gen) return;
        const r = model.rules[i], ins = er.filter(x => x.r === i), hit = ins.filter(x => fired[x.e]);
        const unmeasured = ins.some(x => model.engines[x.e].why.kind === 'unmeasured' || model.engines[x.e].why.kind === 'unknown');
        if (hit.length) {
          hit.forEach(x => x.p.setAttribute('class', 'fa-edge lit'));
          await Promise.all(hit.map(x => fly(clock, svg, x.p, 500)));
          const disabled = r.applicability === 'disabled' || ['DISABLED', 'DISABLE', 'OFF'].includes(String(r.state).toUpperCase());
          R[i].set(disabled ? 'after' : 'warn'); R[i].sub(disabled ? 'disabled; does not act' : `candidate · ${r.action || 'action unverified'}`);
        } else if (unmeasured) {
          R[i].set('warn'); R[i].sub(`${r.action || ''} · fires if its engine does`.replace(/^ · /, ''));
        } else {
          ins.forEach(x => x.p.setAttribute('class', 'fa-edge dead')); R[i].set('after'); R[i].sub('no confirmed engine match');
        }
      }
    }
    return { play, destroy() { gen++; clock.destroy(); host.innerHTML = ''; } };
  }
  // The words for a drill model: what fired, what nearly fired, and why.
  function drillSummary(m) {
    if (!m) return '';
    if (!m.measured) return 'Configuration candidates only. Content match counts and actual enforcement are unverified.';
    const fires = m.engines.filter(e => e.why.kind === 'fires'), unknown = m.engines.filter(e => ['unknown', 'unmeasured'].includes(e.why.kind));
    const total = m.totals || { fires: fires.length, unknown: unknown.length };
    const parts = [m.incomplete ? 'Content evaluation is incomplete because configuration could not be read; no no-match conclusion is available.' : total.fires ? `${total.fires} engine(s) satisfy the simulated expression.` : total.unknown ? 'No confirmed engine match; some engine results are unknown.' : 'No engine matches the locally evaluated content.'];
    if (total.unknown) parts.push(`${total.unknown} engine(s) remain unknown; absence of a match is not established.`);
    m.engines.filter(e => e.why.kind === 'near').forEach(e => parts.push(`${e.name} does not fire, ${e.why.text}.`));
    const candidates = m.rules.filter(r => r.applicability !== 'disabled' && !['DISABLED', 'DISABLE', 'OFF'].includes(String(r.state).toUpperCase()) && r.engines.some(i => m.engines[i] && m.engines[i].why.kind === 'fires'));
    if (candidates.length) parts.push('Rule candidates: ' + candidates.map(r => r.name + (r.action ? ` (configured ${r.action})` : ' (action unverified)')).join(', ') + '. Applicability and live action are not proven by content matches.');
    const h = m.hidden || {};
    if (h.engines || h.rules || h.dicts) parts.push(`Not drawn: ${h.engines || 0} engine(s), ${h.rules || 0} rule(s), ${h.dicts || 0} dictionaries; totals include undisplayed engines.`);
    if (m.note) parts.push(m.note);
    return parts.join(' ');
  }

  // ── Deployment graph ─────────────────────────────────────────────
  function graph(host, model, opts) {
    const o = opts || {};
    host.innerHTML = '';
    const clock = animator();
    const C = model.cols.length, W = 1000, BW = Math.min(200, (W - 20) / C - 40), GAP = C > 1 ? (W - 20 - C * BW) / (C - 1) : 0;
    const maxRows = Math.max.apply(null, model.cols.map(c => c.keys.length));
    const RH = 54, H = 36 + maxRows * RH;
    const svg = newSvg(host, W, H, `Deployment plan: ${model.cols.map(c => `${c.keys.length} ${c.label.toLowerCase()}`).join(', ')}`);
    const pos = {};
    model.cols.forEach((c, ci) => {
      const x = 10 + ci * (BW + GAP);
      const lab = svgEl('text', { x: x + BW / 2, y: 16, class: 'fa-col', 'text-anchor': 'middle' }, svg); lab.textContent = c.label;
      const off = (maxRows - c.keys.length) * RH / 2;
      c.keys.forEach((k, ri) => { pos[k] = { x, y: 28 + off + ri * RH, w: BW, h: 40 }; });
    });
    const paths = model.edges.map(e => ({ e, p: curve(svg, pos[e.from], pos[e.to]) }));
    const B = {};
    Object.keys(pos).forEach(k => {
      const n = model.nodes[k];
      const b = box(svg, pos[k].x, pos[k].y, BW, 40, n.name, '', n.tone);
      b.g.setAttribute('tabindex', '0'); b.g.setAttribute('data-key', k);
      b.g.addEventListener('mouseenter', () => trace(k)); b.g.addEventListener('mouseleave', () => trace(null));
      b.g.addEventListener('focus', () => trace(k)); b.g.addEventListener('blur', () => trace(null));
      B[k] = b;
    });
    function related(k) {
      const keep = new Set([k]);
      const walk = (dir) => { const q = [k]; while (q.length) { const c = q.shift(); model.edges.forEach(e => { const nx = dir ? (e.from === c ? e.to : null) : (e.to === c ? e.from : null); if (nx && !keep.has(nx)) { keep.add(nx); q.push(nx); } }); } };
      walk(true); walk(false);
      return keep;
    }
    function trace(k) {
      const keep = k ? related(k) : null;
      Object.keys(B).forEach(x => B[x].g.classList.toggle('dim', !!keep && !keep.has(x)));
      paths.forEach(x => x.p.classList.toggle('lit', !!keep && keep.has(x.e.from) && keep.has(x.e.to)));
      if (o.onTrace) o.onTrace(k ? model.nodes[k] : null, keep);
    }
    // Content streaming along every edge, three dots each.
    const dots = [];
    paths.forEach((x, i) => { for (let j = 0; j < 3; j++) dots.push({ x, t: (j / 3 + i * 0.07) % 1, c: svgEl('circle', { r: 3, class: 'fa-dot small' + (/stop/.test(model.nodes[x.e.to].tone) ? ' bad' : '') }, svg) }); });
    let last = 0, running = false, stopFn = null;
    const tick = now => {
      const dt = Math.min(50, now - (last || now)); last = now;
      dots.forEach(d => { d.t = (d.t + dt / 2600) % 1; const L = d.x.p.getTotalLength(), q = d.x.p.getPointAtLength(L * d.t); d.c.setAttribute('cx', q.x); d.c.setAttribute('cy', q.y); d.c.setAttribute('opacity', (Math.sin(Math.PI * d.t) * 0.9).toFixed(2)); });
    };
    function play() { if (running || reduced()) return; running = true; last = 0; stopFn = clock.add(tick); }
    function pause() { running = false; if (stopFn) stopFn(); stopFn = null; }
    // Replay the order a deploy writes: dictionaries, engines, app
    // groups, rules (templates and prerequisites are read, not written).
    let gen = 0;
    async function replay() {
      const my = ++gen;
      const order = ['dictionary', 'engine', 'app_group', 'policy'];
      const keys = [];
      order.forEach(kind => model.cols.filter(c => c.kind === kind).forEach(c => c.keys.forEach(k => keys.push(k))));
      keys.forEach(k => B[k].set('after'));
      for (const k of keys) {
        if (my !== gen) return;
        B[k].set('on'); await wait(keys.length > 30 ? 90 : 260);
        B[k].set(model.nodes[k].tone);
      }
    }
    if (!reduced()) play();
    return { play, pause, replay, running: () => running, destroy() { gen++; clock.destroy(); host.innerHTML = ''; } };
  }

  // ── Live traffic lanes ───────────────────────────────────────────
  const LIVE_LABEL = { web: 'Inline web', endpoint: 'Endpoint', email: 'Email', saas: 'SaaS API', unknown: 'Unknown channel' };
  function live(host) {
    host.innerHTML = '';
    const clock = animator();
    const svg = newSvg(host, 1000, 465, 'Live DLP incidents moving through channel, dictionaries, engine, rule, action and Workflow Automation');
    const cap = {}, rule = {};
    LIVE_CHANNELS.forEach((c, i) => {
      cap[c] = box(svg, 8, 12 + i * 70, 130, 46, LIVE_LABEL[c], '0 incidents');
      rule[c] = box(svg, 560, 12 + i * 70, 150, 46, LIVE_LABEL[c] + ' rule', '');
    });
    const dic = box(svg, 200, 127, 140, 46, 'Dictionaries', 'match counts');
    const eng = box(svg, 385, 127, 130, 46, 'Engine', 'verdict');
    const enf = box(svg, 760, 50, 105, 46, 'Configured enforce', '0', 'warn');
    const mon = box(svg, 760, 200, 105, 46, 'Configured monitor', '0', 'warn');
    const unk = box(svg, 760, 300, 105, 46, 'Action unknown', '0', 'warn');
    const wa = box(svg, 895, 127, 100, 46, 'Workflow', 'Automation');
    const P = {};
    LIVE_CHANNELS.forEach(c => { P['c' + c] = curve(svg, cap[c], dic); P['r' + c] = curve(svg, eng, rule[c]); P['e' + c] = curve(svg, rule[c], enf); P['m' + c] = curve(svg, rule[c], mon); P['u' + c] = curve(svg, rule[c], unk); });
    P.de = curve(svg, dic, eng); P.ew = curve(svg, enf, wa); P.mw = curve(svg, mon, wa); P.uw = curve(svg, unk, wa);
    const controlCaption = svgEl('text', { x: 10, y: 387, class: 'fa-s' }, svg);
    controlCaption.textContent = 'Upstream controls: not observed in this incident feed';
    const controls = ['URL Filtering', 'SSL Inspection', 'File Type Control'].map((label, i) => box(svg, 10 + i * 330, 398, 310, 46, label, 'unverified · no telemetry', 'warn'));
    const n = { web: 0, endpoint: 0, email: 0, saas: 0, unknown: 0, enforced: 0, monitor: 0, unknown_action: 0 };
    let queue = Promise.resolve();
    function push(m) {
      if (!m) return;
      queue = queue.then(async () => {
        const c = LIVE_CHANNELS.includes(m.channel) ? m.channel : 'unknown', ok = m.enforcement === 'enforced', unknown = m.enforcement !== 'enforced' && m.enforcement !== 'monitor';
        const cls = ok ? 'bad' : 'warn';
        controlCaption.textContent = `Current incident: ${LIVE_LABEL[c]} · upstream enforcement is not inferred`;
        (m.controls || liveModel(m).controls).forEach((control, i) => {
          controls[i].sub(control.status === 'not_applicable' ? 'not applicable to this channel' : 'unverified · no telemetry');
          controls[i].set(control.status === 'not_applicable' ? 'after' : 'warn');
        });
        cap[c].set('on');
        await fly(clock, svg, P['c' + c], 450, cls);
        cap[c].set(''); n[c]++; cap[c].sub(`${n[c]} incident${n[c] === 1 ? '' : 's'}`);
        dic.sub(m.dicts[0] ? clip(`${m.dicts[0].name}: ${m.dicts[0].count}`, 22) : 'match counts');
        await fly(clock, svg, P.de, 300, cls);
        eng.sub(clip(m.engine || 'verdict', 20));
        await fly(clock, svg, P['r' + c], 350, cls);
        rule[c].sub(clip(m.rule, 22)); rule[c].set(ok ? 'stop' : 'warn');
        await fly(clock, svg, P[(ok ? 'e' : unknown ? 'u' : 'm') + c], 350, cls);
        n[ok ? 'enforced' : unknown ? 'unknown_action' : 'monitor']++; (ok ? enf : unknown ? unk : mon).sub(String(n[ok ? 'enforced' : unknown ? 'unknown_action' : 'monitor']));
        await fly(clock, svg, ok ? P.ew : unknown ? P.uw : P.mw, 300, cls);
        rule[c].set('');
      }).catch(() => {});
      return queue;
    }
    return { push, counts: () => Object.assign({}, n), destroy() { clock.destroy(); host.innerHTML = ''; } };
  }

  // ── Architecture flow steps ──────────────────────────────────────
  // flow: an ARCH entry; overlay: {hopKey: tone} from a path result.
  function steps(host, flow, overlay, opts) {
    const o = opts || {};
    host.innerHTML = '';
    const clock = animator();
    const per = 4, BW = 205, BH = 50, W = 1000, GAP = (W - 20 - per * BW) / (per - 1), ROWH = 88;
    const n = flow.steps.length, rows = Math.ceil(n / per);
    const svg = newSvg(host, W, rows * ROWH + 6, `${flow.title}: ${flow.steps.map(s => s.t).join(', then ')}`);
    const pos = flow.steps.map((s, i) => { const r = Math.floor(i / per), c = i % per, col = r % 2 ? per - 1 - c : c; return { x: 10 + col * (BW + GAP), y: 8 + r * ROWH, r }; });
    const edges = [];
    for (let i = 0; i < n - 1; i++) {
      const a = pos[i], b = pos[i + 1]; let d;
      if (a.r !== b.r) d = `M${a.x + BW / 2} ${a.y + BH} L${b.x + BW / 2} ${b.y}`;
      else if (a.r % 2 === 0) d = `M${a.x + BW} ${a.y + BH / 2} L${b.x} ${b.y + BH / 2}`;
      else d = `M${a.x} ${a.y + BH / 2} L${b.x + BW} ${b.y + BH / 2}`;
      edges.push(svgEl('path', { d, class: 'fa-edge' }, svg));
    }
    const ownTone = s => {
      if (!overlay || !s.hop) return '';
      const ts = s.hop.map(k => overlay[k]).filter(Boolean);
      return ts.indexOf('stop') >= 0 ? 'stop' : ts.indexOf('warn') >= 0 ? 'warn' : ts.indexOf('pass') >= 0 ? 'pass' : ts.length ? 'after' : '';
    };
    // Past the step where the traffic stops, nothing happens to it.
    let stopAt = -1;
    flow.steps.forEach((s, k) => { if (stopAt < 0 && ownTone(s) === 'stop') stopAt = k; });
    const toneOf = s => { const k = flow.steps.indexOf(s); return stopAt >= 0 && k > stopAt ? 'after' : ownTone(s); };
    const B = flow.steps.map((s, i) => {
      const b = box(svg, pos[i].x, pos[i].y, BW, BH, `${i + 1}. ${s.t}`, s.gate ? 'often missed' : '', s.gate ? 'gate' : '');
      return b;
    });
    let i = -1, gen = 0;
    function land(k) {
      const s = flow.steps[k], t = toneOf(s);
      B[k].set(['on', t, s.gate ? 'gate' : ''].filter(Boolean).join(' '));
      if (o.onStep) o.onStep(s, k, t);
    }
    function reset() { gen++; i = -1; B.forEach((b, k) => b.set(flow.steps[k].gate ? 'gate' : '')); edges.forEach(e => e.setAttribute('class', 'fa-edge')); }
    async function stepOnce() {
      const my = gen;
      if (i >= n - 1) return false;
      if (i >= 0) { edges[i].setAttribute('class', 'fa-edge lit'); await fly(clock, svg, edges[i], 550); if (my !== gen) return false; B[i].set([toneOf(flow.steps[i]) || 'pass', flow.steps[i].gate ? 'gate' : ''].filter(Boolean).join(' ')); }
      i++; land(i);
      return i < n - 1;
    }
    async function play() {
      reset(); const my = gen;
      while (my === gen && await stepOnce()) await wait(o.slow && o.slow() ? 1600 : 900);
    }
    reset();
    return { play, step() { if (i >= n - 1) reset(); return stepOnce(); }, reset, destroy() { gen++; clock.destroy(); host.innerHTML = ''; } };
  }

  // ── Traffic motion: Data Flow Map, SSL flow, SSL coverage ────────
  // Three more pictures, each drawn from the result its page already
  // shows. The numbers they carry are the page's own (report.summary,
  // volume.protocols[unit], summary.by_kind): a model never counts a
  // second way. Where it splits a page number (bypassed at Client
  // Connector vs at the PAC file) the parts are checked to add up to it,
  // and `mismatch` says so if they ever do not.
  const pctOf = (n, d) => (d ? n / d : 0);
  const fmt1 = n => String(Math.round(n * 10) / 10);
  const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + 's')}`;

  // Sankey-style river model: {cols, nodes: [{key, col, label, value,
  // tone, exit, sub}], links: [{key, from, to, value, tone, label,
  // items}], routes: [{links, weight, tone}], total, unit, alt}.
  function riverAdd(m, from, to, extra) {
    const key = from + '>' + to;
    let l = m.links.filter(x => x.key === key)[0];
    if (!l) { l = Object.assign({ key, from, to, value: 0, items: [] }, extra || {}); m.links.push(l); }
    return l;
  }

  // Data Flow Map report → every traced path (traffic class × network)
  // as a stream: Client Connector → PAC → URL filtering and Cloud App
  // Control → SSL inspection (split: decrypted / still encrypted) → Web
  // DLP → incident receiver, in the order the tracer walks the hops.
  const DF_COLS = ['Traffic', 'Client Connector', 'PAC file', 'URL filtering and Cloud App Control', 'SSL inspection', 'Web DLP', 'DLP outcome', 'Incident receiver'];
  const DF_NODES = {
    src: [0, 'Traffic classes × networks', 'idle'],
    cc: [1, 'Client Connector', 'pass'], x_cc: [2, 'Bypassed at Client Connector', 'stop', 'bypass'], u_cc: [2, 'Routing unverified', 'warn', 'unverified'],
    pac: [2, 'PAC file', 'pass'], x_pac: [3, 'PAC file sends it direct', 'stop', 'bypass'], u_pac: [3, 'PAC answer unverified', 'warn', 'unverified'],
    policy: [3, 'URL filtering and Cloud App Control', 'pass'], b_policy: [4, 'Blocked by URL filtering or Cloud App Control', 'block', 'blocked'],
    ssl: [4, 'SSL inspection', 'pass'], b_ssl: [5, 'Blocked at SSL inspection', 'block', 'blocked'], u_ssl: [5, 'Inspection unverified', 'warn', 'unverified'],
    enc: [5, 'Still encrypted: DLP blind', 'stop'], dlp: [5, 'Decrypted: Web DLP', 'pass'],
    o_block: [6, 'Blocked by File Type Control', 'block', 'blocked'], o_enforce: [6, 'A DLP rule can block', 'pass'],
    o_monitor: [6, 'DLP monitors only', 'warn'], o_other: [6, 'No DLP rule, or unverified', 'warn'],
    incident: [7, 'Incident receiver configured', 'pass'],
  };
  const DF_ORDER = ['src', 'cc', 'x_cc', 'u_cc', 'pac', 'x_pac', 'u_pac', 'policy', 'b_policy', 'ssl', 'dlp', 'enc', 'b_ssl', 'u_ssl', 'o_enforce', 'o_monitor', 'o_other', 'o_block', 'incident'];
  const SSL_UNVERIFIED = ['unknown', 'out_of_scope', 'conditional', 'not_reached', 'skipped', 'na'];

  // The route one trace takes, by the same tests the report's summary
  // uses: bypassed = !reaches_zscaler; left encrypted = !conditional,
  // reaches, outcome not blocked, SSL hop blind; enforce / monitor = the
  // outcome. Returns node keys, first to last.
  function dfRoute(t) {
    const hop = k => (t.hops || []).filter(h => h.key === k)[0] || {};
    const firstOf = (keys, st) => keys.filter(k => st.indexOf(hop(k).status) >= 0)[0];
    const r = ['src', 'cc'];
    if (!t.reaches_zscaler) {
      if (firstOf(['zcc', 'forwarding', 'pac'], ['bypass']) === 'pac') return r.concat(['pac', 'x_pac']);
      return r.concat(['x_cc']);
    }
    if (t.conditional) {
      return firstOf(['zcc', 'forwarding'], ['unknown', 'warn']) || hop('pac').status !== 'unknown' ? r.concat(['u_cc']) : r.concat(['pac', 'u_pac']);
    }
    r.push('pac', 'policy');
    const blockedAt = t.outcome === 'blocked' ? firstOf(['cac', 'url', 'ssl', 'ftc'], ['blocked']) : null;
    if (blockedAt === 'cac' || blockedAt === 'url') return r.concat(['b_policy']);
    r.push('ssl');
    const ssl = hop('ssl').status;
    if (blockedAt === 'ssl') return r.concat(['b_ssl']);
    if (ssl === 'blind' && t.outcome !== 'blocked') return r.concat(['enc']);
    if (!t.decrypted || SSL_UNVERIFIED.indexOf(ssl) >= 0) return r.concat([t.outcome === 'blocked' ? 'b_ssl' : 'u_ssl']);
    r.push('dlp');
    if (t.outcome === 'blocked') return r.concat(['o_block']);
    r.push(t.outcome === 'enforce' ? 'o_enforce' : t.outcome === 'monitor' ? 'o_monitor' : 'o_other');
    if (hop('incident').status === 'conditional') r.push('incident');
    return r;
  }

  function dataFlowModel(report) {
    if (!report || !Array.isArray(report.traces) || !report.summary) return null;
    const s = report.summary, nets = {};
    (report.networks || []).forEach(n => { nets[n.key] = n.label || n.key; });
    const m = { kind: 'dataflow', cols: DF_COLS.slice(), nodes: [], links: [], routes: [], total: s.traces, unit: 'paths', summary: {}, counts: {}, mismatch: [] };
    ['traces', 'bypassed', 'blind', 'enforced', 'monitored'].forEach(k => { m.summary[k] = s[k]; });
    const value = {}, items = {};
    report.traces.forEach((t, i) => {
      const route = dfRoute(t);
      const name = `${(t.destination || {}).label || 'Destination'} · ${nets[t.network] || t.network || ''}`;
      route.forEach(k => { value[k] = (value[k] || 0) + 1; (items[k] = items[k] || []).push(i); });
      const keys = [];
      for (let j = 1; j < route.length; j++) {
        const l = riverAdd(m, route[j - 1], route[j]);
        l.value++; l.items.push({ i, name });
        keys.push(l.key);
      }
      const end = DF_NODES[route[route.length - 1]];
      m.routes.push({ links: keys, weight: 1, tone: end[2], item: i, end: route[route.length - 1] });
    });
    DF_ORDER.forEach(k => {
      if (!value[k]) return;
      const d = DF_NODES[k];
      m.nodes.push({ key: k, col: d[0], label: d[1], tone: d[2], exit: d[3] || '', value: value[k], items: items[k] });
    });
    const n = k => value[k] || 0;
    m.counts = {
      traces: report.traces.length, bypassed: n('x_cc') + n('x_pac'), bypassed_cc: n('x_cc'), bypassed_pac: n('x_pac'),
      unverified_route: n('u_cc') + n('u_pac'), blocked: n('b_policy') + n('b_ssl') + n('o_block'),
      blocked_policy: n('b_policy'), blocked_ssl: n('b_ssl'), blocked_ftc: n('o_block'), blind: n('enc'), unverified_ssl: n('u_ssl'),
      decrypted: n('dlp'), enforced: n('o_enforce'), monitored: n('o_monitor'), other: n('o_other'), incident: n('incident'),
    };
    // Every path ends in exactly one place, and the named streams are
    // the summary's own numbers.
    const terminal = ['x_cc', 'x_pac', 'u_cc', 'u_pac', 'b_policy', 'b_ssl', 'u_ssl', 'enc', 'o_block', 'o_enforce', 'o_monitor', 'o_other'];
    m.terminals = terminal.filter(k => value[k]).map(k => ({ key: k, label: DF_NODES[k][1], tone: DF_NODES[k][2], count: n(k), share: pctOf(n(k), s.traces) }));
    [['traces', 'traces'], ['bypassed', 'bypassed'], ['blind', 'blind'], ['enforced', 'enforced'], ['monitored', 'monitored']].forEach(p => {
      if (m.counts[p[1]] !== s[p[0]]) m.mismatch.push(`${p[0]}: picture ${m.counts[p[1]]}, summary ${s[p[0]]}`);
    });
    m.links.forEach(l => {
      const to = DF_NODES[l.to];
      l.tone = to[2];
      l.label = `${DF_NODES[l.from][1]} → ${to[1]}: ${plural(l.value, 'path')} of ${s.traces} (${Math.round(100 * pctOf(l.value, s.traces))}%)`;
    });
    const nNets = (report.networks || []).length, nDest = s.destinations;
    m.label = `Traffic flow: ${plural(s.traces, 'traced path')}${nDest ? ` (${nDest} traffic classes × ${nNets} networks)` : ''} through Client Connector, the PAC file, URL filtering and Cloud App Control, SSL inspection, Web DLP and the incident receiver`;
    const c = m.counts;
    m.alt = [
      `${plural(s.traces, 'path')} traced${nDest ? `: ${nDest} traffic classes on ${nNets} networks` : ''}. Each stream is as wide as its share of them.`,
      `Never reach Zscaler: ${s.bypassed}${s.bypassed ? ` (${c.bypassed_cc} bypassed at Client Connector, ${c.bypassed_pac} sent direct by the PAC file)` : ''}.`,
      c.unverified_route ? `Routing unverified (Client Connector or PAC answer not known): ${c.unverified_route}.` : '',
      c.blocked ? `Blocked before content inspection: ${c.blocked} (${c.blocked_policy} by URL filtering or Cloud App Control, ${c.blocked_ssl} at SSL inspection, ${c.blocked_ftc} by File Type Control).` : '',
      `Reach ZIA, left encrypted (Web DLP is blind): ${s.blind}.`,
      c.unverified_ssl ? `SSL inspection unverified (not in scope or not read): ${c.unverified_ssl}.` : '',
      `Decrypted: ${c.decrypted}. A DLP rule can block: ${s.enforced}. DLP monitors only: ${s.monitored}. No DLP rule, or unverified: ${c.other}.`,
      c.decrypted ? `A covering rule names the Incident Receiver or an ICAP server on ${plural(c.incident, 'path')}; delivery is not verified.` : '',
    ].filter(Boolean);
    return m;
  }

  // SSL flow report + one traffic class → the SSL rules a request meets
  // in evaluation order (first match wins). Exemptions scoped to some
  // users peel packets off; the deciding rule turns the rest; the
  // certificate and TLS-version checks of that rule are gates on the way
  // to inline Web DLP.
  const SSL_DECISION = { inspected: 'Decrypt', not_inspected: 'Do not decrypt', blocked: 'Block', no_rule: 'No rule', unknown: 'Unverified' };
  const SSL_DLP = { unknown: 'Web DLP unverified', enforcing: 'Web DLP enforcing', monitor: 'Web DLP monitor only', none: 'No inline Web DLP rule',
    blind: 'Web DLP blind (still encrypted)', blocked: 'Traffic blocked', not_in_scope: 'Web DLP not in scope' };
  const tlsWord = v => String(v || '').replace(/^(CLIENT|SERVER)_/, '').replace(/^TLS_(\d)_(\d)$/, 'TLS $1.$2').replace(/_/g, ' ');
  function sslGates(checks, decision) {
    if (decision !== 'inspected' && decision !== 'not_inspected') return [];
    const c = checks || null;
    const cert = !c ? [] : [c.server_certificates ? `untrusted certificate: ${c.server_certificates.replace(/_/g, ' ').toLowerCase()}` : '',
      c.ocsp_check === true ? 'OCSP revocation check on' : c.ocsp_check === false ? 'OCSP revocation check off' : '',
      c.block_no_sni === true ? 'no SNI: blocked' : ''].filter(Boolean);
    const tls = !c ? [] : [c.min_client_tls ? `client at least ${tlsWord(c.min_client_tls)}` : '', c.min_server_tls ? `server at least ${tlsWord(c.min_server_tls)}` : ''].filter(Boolean);
    const gate = (key, label, parts) => ({ key, label, known: parts.length > 0, parts: parts.length ? parts : ['not in the rule data'], text: parts.length ? parts.join('; ') : 'not in the rule data' });
    return [gate('cert', 'Certificate check', cert), gate('tls', 'TLS version check', tls)];
  }
  function sslWalkModel(rep, key) {
    if (!rep || !Array.isArray(rep.classes) || !rep.classes.length) return null;
    const c = rep.classes.filter(x => x.key === key)[0] || rep.classes[0];
    const exc = {};
    (c.exceptions || []).forEach(e => { exc[String(e.id)] = e; });
    const d = c.decided_by || null, dId = d ? String(d.id) : null;
    const steps = [];
    let skip = [], decided = false, after = 0;
    const flush = () => { if (skip.length) { steps.push({ kind: 'skip', count: skip.length, names: skip.slice(0, 6), text: `${plural(skip.length, 'rule')} ${skip.length === 1 ? 'does' : 'do'} not match this traffic` }); skip = []; } };
    const enabled = (rep.ssl_rules || []).filter(r => r && r.enabled !== false);
    enabled.forEach(r => {
      const id = String(r.id);
      if (decided) { after++; return; }
      if (dId !== null && id === dId) {
        flush(); decided = true;
        steps.push({ kind: 'decide', name: r.name, order: r.order, action: r.action, decision: d.decision, text: `${SSL_DECISION[d.decision] || d.action}: decides for everyone else` });
        return;
      }
      if (exc[id]) {
        flush();
        const e = exc[id], scope = (e.scope || []).join(', ') || 'some users';
        steps.push({ kind: 'exception', name: r.name, order: r.order, action: r.action, decision: e.decision, scope, peel: true,
          text: e.decision === 'inspected' ? `Decrypts only for its scope (${scope})` : e.decision === 'blocked' ? `Blocks its scope (${scope})` : `Do not decrypt for its scope (${scope})` });
        return;
      }
      skip.push(r.name);
    });
    flush();
    if (!decided && c.decision !== 'unknown') steps.push({ kind: 'none', name: 'No enabled rule matches', decision: 'no_rule', text: 'Nothing decrypts it: it passes encrypted' });
    const shadowed = (c.shadowed || []).map(r => r.name);
    if (after) steps.push({ kind: 'after', count: after, shadowed, text: `${plural(after, 'later rule')} never run for this traffic` });
    const decision = c.decision;
    const gates = sslGates(d && d.checks, decision);
    const dlp = { status: c.dlp_status, label: SSL_DLP[c.dlp_status] || String(c.dlp_status || '') };
    const tone = decision === 'inspected' ? (c.dlp_status === 'enforcing' ? 'pass' : 'warn') : decision === 'blocked' ? 'block' : decision === 'unknown' ? 'warn' : 'stop';
    const peels = steps.filter(x => x.kind === 'exception');
    const alt = [`${c.label}: a request meets the enabled SSL inspection rules in order; the first rule that matches decides.`];
    steps.forEach(x => {
      if (x.kind === 'skip') alt.push(`${x.text}: ${x.names.join(', ')}${x.count > x.names.length ? ', …' : ''}.`);
      else if (x.kind === 'exception') alt.push(`${x.name} (order ${x.order}): ${x.text}; those packets leave the stream here.`);
      else if (x.kind === 'decide') alt.push(`${x.name} (order ${x.order}) decides: ${x.action}.`);
      else alt.push(`${x.text}${x.kind === 'after' && x.shadowed.length ? `, including the decrypt rule${x.shadowed.length === 1 ? '' : 's'} ${x.shadowed.join(', ')} (shadowed)` : ''}.`);
    });
    gates.forEach(g => alt.push(`Gate: ${g.label}: ${g.text}.`));
    alt.push(`Then: ${dlp.label}.`);
    return { kind: 'sslwalk', key: c.key, label: c.label, decision, decider: d ? { name: d.name, order: d.order, action: d.action } : null,
      steps, gates, dlp, tone, peels: peels.length, alt, unknown: decision === 'unknown' };
  }

  // SSL coverage result → a traffic river (bytes or transactions from
  // the page's Insights numbers: SSL/TLS against HTTP, inspected against
  // not) and a causes fan (each kind of cause as wide as its share of the
  // causes found). Insights cannot measure traffic per rule or category,
  // so the fan is drawn on its own scale and says so.
  const COVER_GROUPS = [
    { key: 'dni', label: 'Do not inspect rules', kinds: ['ssl_rule', 'ssl_rule_scoped', 'catch_all', 'scoped_catch_all'], reaches: true },
    { key: 'exempt', label: 'Certificate-pinned exemptions', kinds: ['pinned_exemptions'], reaches: true },
    { key: 'zcc', label: 'Client Connector bypass', kinds: ['zcc_domains', 'zcc_ips', 'zcc_apps', 'zcc_processes', 'zcc_vpn_gateways', 'forwarding_none'], reaches: false },
    { key: 'pac', label: 'PAC file bypass', kinds: ['pac_direct'], reaches: false },
  ];
  function sslCoverageModel(res, unit, fmt) {
    if (!res || !res.summary) return null;
    const f = Object.assign({ amount: v => String(v), pct: p => (p == null ? 'not measurable' : `${fmt1(p)}%`) }, fmt || {});
    const s = res.summary, v = res.volume || {};
    const sel = v.available && v.protocols ? v.protocols[unit] : null;
    const out = { kind: 'sslcoverage', unit, traffic: null, causes: null, alt: [], note: '' };
    if (sel && (sel.ssl_total + sel.http_total) > 0) {
      const b = sel.buckets || {};
      const T = sel.ssl_total + sel.http_total, ins = (b.ssl_inspected || 0) + (b.http || 0);
      const unPct = sel.ssl_pct == null ? null : Math.round((100 - sel.ssl_pct) * 10) / 10;
      const m = { cols: ['Traffic', 'Protocol', 'Inspection'], nodes: [], links: [], routes: [], total: T, unit };
      const node = (key, col, label, value, tone, sub, exit) => { if (value > 0) m.nodes.push({ key, col, label, value, tone, sub: sub || f.amount(value), exit: exit || '' }); };
      node('reach', 0, 'Web traffic reaching Zscaler', T, 'idle');
      node('ssl', 1, 'SSL/TLS (HTTPS)', sel.ssl_total, 'idle');
      node('http', 1, 'HTTP (cleartext)', sel.http_total, 'idle');
      node('ins', 2, 'Inspected', ins, 'pass', `${f.pct(sel.total_pct)} of SSL/TLS and HTTP`);
      node('unins', 2, 'Not inspected', b.ssl_not_inspected || 0, 'stop', `${f.amount(b.ssl_not_inspected || 0)} left encrypted`);
      if (sel.other_total > 0) { node('other', 0, 'Other / not classified', sel.other_total, 'idle'); node('other_x', 1, 'Left out of the percentages', sel.other_total, 'idle', f.amount(sel.other_total), 'apart'); }
      const link = (from, to, value, tone, label) => { if (value > 0) { const l = riverAdd(m, from, to, { tone, label }); l.value = value; } };
      link('reach', 'ssl', sel.ssl_total, 'idle', `SSL/TLS: ${f.amount(sel.ssl_total)}`);
      link('reach', 'http', sel.http_total, 'idle', `HTTP: ${f.amount(sel.http_total)}`);
      link('ssl', 'ins', b.ssl_inspected || 0, 'pass', `SSL/TLS inspected: ${f.pct(sel.ssl_pct)} (${f.amount(b.ssl_inspected || 0)})`);
      link('ssl', 'unins', b.ssl_not_inspected || 0, 'stop', `SSL/TLS not inspected: ${f.pct(unPct)} (${f.amount(b.ssl_not_inspected || 0)})`);
      link('http', 'ins', sel.http_total, 'pass', `HTTP inspected: ${f.pct(sel.http_pct)} (cleartext, ${f.amount(sel.http_total)})`);
      link('other', 'other_x', sel.other_total || 0, 'idle', `Other / not classified: ${f.amount(sel.other_total || 0)}, left out of the percentages`);
      const route = (keys, w, tone) => { if (w > 0) m.routes.push({ links: keys, weight: w, tone }); };
      route(['reach>ssl', 'ssl>ins'], b.ssl_inspected || 0, 'pass');
      route(['reach>ssl', 'ssl>unins'], b.ssl_not_inspected || 0, 'stop');
      route(['reach>http', 'http>ins'], sel.http_total, 'pass');
      route(['other>other_x'], sel.other_total || 0, 'idle');
      m.shares = { ssl_inspected_pct: sel.ssl_pct, ssl_not_inspected_pct: unPct, http_pct: sel.http_pct, total_pct: sel.total_pct };
      m.label = `Traffic river by ${unit === 'BYTES' ? 'bytes' : 'transactions'}: SSL/TLS ${f.amount(sel.ssl_total)}, HTTP ${f.amount(sel.http_total)}; ${f.pct(sel.total_pct)} inspected`;
      out.traffic = m;
      out.alt.push(`Web traffic reaching Zscaler, by ${unit === 'BYTES' ? 'bytes' : 'transactions'}: SSL/TLS ${f.amount(sel.ssl_total)} and HTTP ${f.amount(sel.http_total)}.`,
        `SSL/TLS: ${f.pct(sel.ssl_pct)} inspected, ${f.pct(unPct)} left encrypted (${f.amount(b.ssl_not_inspected || 0)}). HTTP: ${f.pct(sel.http_pct)} inspected (cleartext).`,
        `In total ${f.pct(sel.total_pct)} of SSL/TLS and HTTP is inspected.` + (sel.other_total > 0 ? ` Other / not classified (${f.amount(sel.other_total)}) is left out of the percentages.` : ''));
    } else if (s.classes_total) {
      // No traffic numbers: the river of kinds of traffic the page counts.
      const m = { cols: ['Kinds of traffic', 'SSL decision'], nodes: [], links: [], routes: [], total: s.classes_total, unit: 'kinds' };
      m.nodes.push({ key: 'kinds', col: 0, label: 'Kinds of web traffic', value: s.classes_total, tone: 'idle', sub: plural(s.classes_total, 'kind') });
      if (s.classes_covered) m.nodes.push({ key: 'cov', col: 1, label: 'Decrypted or blocked', value: s.classes_covered, tone: 'pass', sub: `${s.classes_covered} (${f.pct(s.class_coverage_pct)})` });
      if (s.classes_not_inspected) m.nodes.push({ key: 'enc', col: 1, label: 'Left encrypted', value: s.classes_not_inspected, tone: 'stop', sub: String(s.classes_not_inspected) });
      if (s.classes_covered) { const l = riverAdd(m, 'kinds', 'cov', { tone: 'pass', label: `Decrypted or blocked: ${s.classes_covered} of ${s.classes_total} kinds (${f.pct(s.class_coverage_pct)})` }); l.value = s.classes_covered; m.routes.push({ links: [l.key], weight: l.value, tone: 'pass' }); }
      if (s.classes_not_inspected) { const l = riverAdd(m, 'kinds', 'enc', { tone: 'stop', label: `Left encrypted: ${s.classes_not_inspected} of ${s.classes_total} kinds` }); l.value = s.classes_not_inspected; m.routes.push({ links: [l.key], weight: l.value, tone: 'stop' }); }
      m.label = `Kinds of web traffic: ${s.classes_covered} of ${s.classes_total} decrypted or blocked`;
      out.traffic = m;
      out.note = 'Traffic numbers were not read, so the river shows kinds of web traffic, not bytes.';
      out.alt.push(`Traffic numbers were not read. Of ${plural(s.classes_total, 'kind')} of web traffic, ${s.classes_covered} ${s.classes_covered === 1 ? 'is' : 'are'} decrypted or blocked (${f.pct(s.class_coverage_pct)}) and ${s.classes_not_inspected} left encrypted.`);
    }
    const byKind = s.by_kind || {}, N = s.causes || 0;
    if (N > 0) {
      const m = { cols: ['Causes', 'Kind of cause', 'Where it acts'], nodes: [], links: [], routes: [], total: N, unit: 'causes' };
      const known = {};
      const groups = COVER_GROUPS.map(g => { g.kinds.forEach(k => { known[k] = 1; }); return { key: g.key, label: g.label, reaches: g.reaches, count: g.kinds.reduce((a, k) => a + (byKind[k] || 0), 0) }; });
      const rest = Object.keys(byKind).filter(k => !known[k]).reduce((a, k) => a + byKind[k], 0);
      if (rest) groups.push({ key: 'other', label: 'Other causes', reaches: true, count: rest });
      m.nodes.push({ key: 'all', col: 0, label: 'Causes found', value: N, tone: 'idle', sub: plural(N, 'cause') });
      let reach = 0, never = 0;
      groups.forEach(g => {
        if (!g.count) return;
        g.share = pctOf(g.count, N);
        m.nodes.push({ key: g.key, col: 1, label: g.label, value: g.count, tone: g.reaches ? 'warn' : 'stop', sub: `${g.count} (${Math.round(100 * g.share)}% of causes)` });
        const l = riverAdd(m, 'all', g.key, { tone: g.reaches ? 'warn' : 'stop', label: `${g.label}: ${plural(g.count, 'cause')}, ${Math.round(100 * g.share)}% of the ${N}` }); l.value = g.count;
        const to = g.reaches ? 'reach' : 'never';
        const l2 = riverAdd(m, g.key, to, { tone: g.reaches ? 'warn' : 'stop', label: `${g.label}: ${g.reaches ? 'reaches Zscaler, left encrypted' : 'never reaches Zscaler'}` }); l2.value = g.count;
        if (g.reaches) reach += g.count; else never += g.count;
        m.routes.push({ links: [l.key, l2.key], weight: g.count, tone: g.reaches ? 'warn' : 'stop' });
      });
      if (reach) m.nodes.push({ key: 'reach', col: 2, label: 'Reaches Zscaler, left encrypted', value: reach, tone: 'warn', sub: plural(reach, 'cause') });
      if (never) m.nodes.push({ key: 'never', col: 2, label: 'Never reaches Zscaler', value: never, tone: 'stop', exit: 'bypass', sub: `${plural(never, 'cause')}, not in the numbers` });
      m.groups = groups.filter(g => g.count);
      m.label = `Why traffic is not inspected: ${plural(N, 'cause')}, ${m.groups.map(g => `${g.label} ${g.count}`).join(', ')}`;
      out.causes = m;
      out.alt.push(`Causes found: ${N}. ` + m.groups.map(g => `${g.label}: ${g.count} (${Math.round(100 * g.share)}%)${g.reaches ? '' : ', never reaches Zscaler'}`).join('; ') + '. Branch width is the share of the causes: Insights cannot measure traffic per rule or category.');
    }
    return out;
  }

  // ── River renderer: streams as wide as their share, packets in them ──
  // opts: onFocus(link|null), onPick(link), height (px of the full total).
  function river(host, model, opts) {
    const o = opts || {};
    host.innerHTML = '';
    const clock = animator();
    const W = 1000, BAR = 12, PADR = 150, C = model.cols.length;
    const step = C > 1 ? (W - 10 - PADR - BAR) / (C - 1) : 0;
    const SCALE = (o.height || 200) / Math.max(1, model.total);
    const LABEL_H = 40, GAP = 12, TOP = 26;
    const pos = {}, colY = {};
    model.nodes.forEach(nd => {
      const h = Math.max(3, nd.value * SCALE), slot = Math.max(h, LABEL_H);
      const y = (colY[nd.col] || TOP);
      pos[nd.key] = { x: 10 + nd.col * step, y: y + (slot - h) / 2, h };
      colY[nd.col] = y + slot + GAP;
    });
    const H = Math.max.apply(null, Object.keys(colY).map(k => colY[k]).concat([TOP + 60])) + 6;
    const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, role: 'group', 'aria-label': model.label || 'Traffic flow', class: 'fa-svg fa-river' });
    host.appendChild(svg);
    model.cols.forEach((label, i) => {
      if (!model.nodes.some(nd => nd.col === i)) return;
      const t = svgEl('text', { x: 10 + i * step, y: 14, class: 'fa-col' }, svg); t.textContent = clip(label, i === C - 1 ? 20 : Math.max(8, Math.floor((step - 8) / 8.2)));
      const tt = svgEl('title', {}, t); tt.textContent = label;
    });
    const linkEl = {}, bands = svgEl('g', { class: 'fa-bands' }, svg);
    const port = {};
    model.nodes.forEach(nd => {
      const outs = model.links.filter(l => l.from === nd.key && pos[l.to]).sort((x, y) => pos[x.to].y - pos[y.to].y);
      const ins = model.links.filter(l => l.to === nd.key && pos[l.from]).sort((x, y) => pos[x.from].y - pos[y.from].y);
      let o1 = 0, i1 = 0;
      outs.forEach(l => { const w = Math.max(2, l.value * SCALE); (port[l.key] = port[l.key] || {}).y1 = pos[nd.key].y + o1 + w / 2; o1 += w; });
      ins.forEach(l => { const w = Math.max(2, l.value * SCALE); (port[l.key] = port[l.key] || {}).y2 = pos[nd.key].y + i1 + w / 2; i1 += w; });
    });
    model.links.forEach(l => {
      const a = pos[l.from], b = pos[l.to];
      if (!a || !b) return;
      const w = Math.max(2, l.value * SCALE);
      const y1 = port[l.key].y1, y2 = port[l.key].y2;
      const x1 = a.x + BAR, x2 = b.x, mx = (x1 + x2) / 2;
      const p = svgEl('path', { d: `M${x1} ${y1} C${mx} ${y1} ${mx} ${y2} ${x2} ${y2}`, class: `fa-band ${l.tone || 'idle'}`, 'stroke-width': w.toFixed(1),
        tabindex: '0', role: 'button', 'aria-label': l.label || l.key, 'data-link': l.key }, bands);
      const tt = svgEl('title', {}, p); tt.textContent = l.label || l.key;
      const focus = on => { p.classList.toggle('on', on); if (o.onFocus) o.onFocus(on ? l : null); };
      p.addEventListener('mouseenter', () => focus(true)); p.addEventListener('mouseleave', () => focus(false));
      p.addEventListener('focus', () => focus(true)); p.addEventListener('blur', () => focus(false));
      const pick = () => { if (o.onPick) o.onPick(l); };
      p.addEventListener('click', pick);
      p.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(); } });
      linkEl[l.key] = p;
    });
    model.nodes.forEach(nd => {
      const p = pos[nd.key];
      const g = svgEl('g', { class: `fa-rnode ${nd.tone || 'idle'}${nd.exit ? ' exit' : ''}`, transform: `translate(${p.x},${p.y})`, 'data-node': nd.key }, svg);
      svgEl('rect', { width: BAR, height: p.h, rx: 2 }, g);
      const ty = -(Math.max(p.h, LABEL_H) - p.h) / 2 + 11;
      const words = String(nd.label), cut = nd.col === C - 1 ? 22 : Math.max(10, Math.floor((step - BAR - 12) / 6.6));
      let l1 = words, l2 = '';
      if (words.length > cut) { const sp = words.lastIndexOf(' ', cut); l1 = words.slice(0, sp > 0 ? sp : cut); l2 = clip(words.slice(l1.length).trim(), cut); }
      const t1 = svgEl('text', { x: BAR + 5, y: ty, class: 'fa-t' }, g); t1.textContent = l1;
      if (l2) { const t2 = svgEl('text', { x: BAR + 5, y: ty + 12, class: 'fa-t' }, g); t2.textContent = l2; }
      const t3 = svgEl('text', { x: BAR + 5, y: ty + (l2 ? 25 : 13), class: 'fa-s' }, g); t3.textContent = clip(nd.sub != null ? nd.sub : `${nd.value} of ${model.total}`, cut + 3);
      if (nd.exit) {
        // The marker a stream leaves the flow with.
        const mk = svgEl('g', { class: `fa-mark ${nd.exit}`, transform: `translate(${-9},${p.h / 2})` }, g);
        svgEl('path', { d: nd.exit === 'bypass' ? 'M-6 -6 L6 6 M-6 6 L6 -6' : nd.exit === 'blocked' ? 'M-6 0 L6 0' : 'M-5 -5 L5 5', class: 'fa-mark-p' }, mk);
      }
      const tt = svgEl('title', {}, g); tt.textContent = `${nd.label}: ${nd.sub != null ? nd.sub : nd.value}`;
    });
    const s = streams(svg, (model.routes || []).map(r => ({ paths: r.links.map(k => linkEl[k]).filter(Boolean), weight: r.weight, tone: r.tone })), { clock, budget: o.budget || 48 });
    if (!reduced() && o.autoplay !== false) s.play();
    return { svg, links: linkEl, play: s.play, pause: s.pause, running: s.running, packets: s.count, destroy() { s.destroy(); clock.destroy(); host.innerHTML = ''; } };
  }

  // Packets along chains of paths, each chain as busy as its weight.
  // routes: [{paths: [SVGPathElement], weight, tone}]. Pure SVG + rAF.
  function streams(svg, routes, opts) {
    const o = opts || {};
    const clock = o.clock || animator(), own = !o.clock;
    const live = routes.filter(r => r.paths.length && r.weight > 0 && r.paths.every(p => p.getTotalLength));
    const total = live.reduce((a, r) => a + r.weight, 0);
    const budget = o.budget || 40, SPEED = o.speed || 0.16;   // px per ms
    const dots = [];
    const layer = svgEl('g', { class: 'fa-packets', 'aria-hidden': 'true' }, svg);
    live.forEach((r, ri) => {
      const lens = r.paths.map(p => p.getTotalLength()), L = lens.reduce((a, b) => a + b, 0);
      if (!L) return;
      const k = Math.max(1, Math.round(budget * r.weight / (total || 1)));
      for (let j = 0; j < k; j++) {
        dots.push({ r, lens, L, phase: (j / k + ri * 0.137) % 1, c: svgEl('circle', { r: 3.2, class: `fa-dot pk ${r.tone || ''}`, opacity: 0 }, layer) });
      }
    });
    let stopFn = null, on = false;
    const tick = now => {
      dots.forEach(d => {
        const dur = d.L / SPEED, prog = ((now / dur) + d.phase) % 1;
        let s = prog * d.L, i = 0;
        while (i < d.lens.length - 1 && s > d.lens[i]) { s -= d.lens[i]; i++; }
        const q = d.r.paths[i].getPointAtLength(Math.min(s, d.lens[i]));
        d.c.setAttribute('cx', q.x.toFixed(1)); d.c.setAttribute('cy', q.y.toFixed(1));
        d.c.setAttribute('opacity', Math.min(1, prog * 12, (1 - prog) * 12).toFixed(2));
      });
    };
    return {
      play() { if (on || !dots.length) return; on = true; stopFn = clock.add(tick); },
      pause() { on = false; if (stopFn) stopFn(); stopFn = null; },
      running: () => on, count: () => dots.length,
      destroy() { on = false; if (stopFn) stopFn(); if (own) clock.destroy(); layer.remove(); },
    };
  }

  // ── Rule walk renderer (SSL flow): the rules a request meets ─────
  function ruleWalk(host, model, opts) {
    const o = opts || {};
    host.innerHTML = '';
    const clock = animator();
    const W = 1000, BW = 330, BH = 46, RH = 66, X = 16, TOP = 8;
    const rows = 1 + model.steps.length;
    const H = TOP + rows * RH + 6;
    const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `${model.label}: the SSL inspection rules in order. ${model.alt.slice(1).join(' ')}`, class: 'fa-svg fa-walk', tabindex: '0', focusable: 'true' });
    host.appendChild(svg);
    const boxTone = model.tone === 'block' ? 'stop' : model.tone;
    const tone = { decide: boxTone, exception: 'warn', skip: 'idle', none: 'stop', after: 'after' };
    const B = [box(svg, X, TOP, BW, BH, `Request: ${model.label}`, 'enters SSL inspection', 'on')];
    model.steps.forEach((s, i) => {
      const title = s.kind === 'skip' || s.kind === 'after' || s.kind === 'none' ? s.text : `${s.order != null ? s.order + '. ' : ''}${s.name}`;
      const sub = s.kind === 'skip' ? clip(s.names.join(', '), 60) : s.kind === 'after' ? (s.shadowed.length ? `shadowed decrypt: ${s.shadowed.join(', ')}` : 'the first match already decided') : s.kind === 'none' ? '' : s.text;
      B.push(box(svg, X, TOP + (i + 1) * RH, BW, BH, title, sub, tone[s.kind] || ''));
    });
    const spine = [];
    for (let i = 0; i < B.length - 1; i++) {
      const a = B[i], b = B[i + 1];
      spine.push(svgEl('path', { d: `M${a.x + BW / 2} ${a.y + BH} L${b.x + BW / 2} ${b.y}`, class: 'fa-edge' + (model.steps[i] && model.steps[i].kind === 'after' ? '' : ' lit') }, svg));
    }
    const routes = [];
    const outX = X + BW + 30;
    const decideIdx = model.steps.map(s => s.kind).indexOf('decide');
    const endIdx = decideIdx >= 0 ? decideIdx : model.steps.map(s => s.kind).indexOf('none');
    model.steps.forEach((s, i) => {
      if (s.kind !== 'exception') return;
      const b = B[i + 1];
      const ex = box(svg, outX, b.y, 250, BH, s.decision === 'inspected' ? `Decrypted for ${s.scope}` : s.decision === 'blocked' ? `Blocked for ${s.scope}` : `Left encrypted for ${s.scope}`,
        s.decision === 'inspected' ? 'Web DLP can see it' : s.decision === 'blocked' ? 'nothing leaves' : 'peeled off: Web DLP is blind', s.decision === 'inspected' ? 'pass' : 'stop');
      const p = svgEl('path', { d: `M${b.x + BW} ${b.y + BH / 2} L${ex.x} ${ex.y + BH / 2}`, class: 'fa-edge ' + (s.decision === 'inspected' ? 'lit' : 'dead') }, svg);
      routes.push({ paths: spine.slice(0, i + 1).concat([p]), weight: 1, tone: s.decision === 'inspected' ? 'pass' : 'stop' });
    });
    if (endIdx >= 0) {
      const b = B[endIdx + 1];
      let prev = { x: b.x + BW, y: b.y + BH / 2 };
      const chain = spine.slice(0, endIdx + 1);
      const gateW = 180, outW = 236;
      let x = outX;
      model.gates.forEach(g => {
        const gb = box(svg, x, b.y, gateW, BH, g.label, g.parts[0], 'gate' + (g.known ? '' : ' idle'));
        gb.g.querySelector('title').textContent = `${g.label}: ${g.text}`;
        if (g.parts.length > 1) { const more = svgEl('text', { x: gb.x + 10, y: gb.y + BH + 12, class: 'fa-why' }, svg); more.textContent = clip(g.parts.slice(1).join(' · '), 34); }
        chain.push(svgEl('path', { d: `M${prev.x} ${prev.y} L${gb.x} ${gb.y + BH / 2}`, class: 'fa-edge lit' }, svg));
        prev = { x: gb.x + gateW, y: gb.y + BH / 2 };
        x += gateW + 12;
      });
      const ob = box(svg, Math.min(x, W - outW - 4), b.y, outW, BH, model.dlp.label, model.decider ? `${model.decider.action}` : 'no rule decided', boxTone);
      chain.push(svgEl('path', { d: `M${prev.x} ${prev.y} L${ob.x} ${ob.y + BH / 2}`, class: 'fa-edge ' + (model.tone === 'stop' ? 'dead' : 'lit') }, svg));
      routes.push({ paths: chain, weight: Math.max(2, 3 - model.peels), tone: model.tone === 'block' ? 'stop' : model.tone });
    }
    const s = streams(svg, routes, { clock, budget: 14, speed: 0.12 });
    if (!reduced() && o.autoplay !== false) s.play();
    return { svg, play: s.play, pause: s.pause, running: s.running, packets: s.count, destroy() { s.destroy(); clock.destroy(); host.innerHTML = ''; } };
  }

  // A Play / Pause button for one or more running pictures (reduced
  // motion: they start still and this button starts them). `handles()`
  // returns the pictures currently on the page.
  function playButton(btn, handles) {
    const all = () => (handles() || []).filter(Boolean);
    const sync = () => {
      const on = all().some(h => h.running());
      btn.textContent = on ? 'Pause motion' : 'Play motion';
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
    };
    btn.addEventListener('click', () => { const on = all().some(h => h.running()); all().forEach(h => (on ? h.pause() : h.play())); sync(); });
    sync();
    return sync;
  }
  // The words for a picture (WCAG 1.1.1): a list next to it, as text.
  function altList(host, lines, id) {
    const ul = root.document.createElement('ul');
    ul.className = 'fa-alt';
    if (id) ul.id = id;
    (lines || []).forEach(t => { const li = root.document.createElement('li'); li.textContent = t; ul.appendChild(li); });
    host.appendChild(ul);
    return ul;
  }

  // ── Samples (labelled as such wherever they are shown) ───────────
  const SAMPLE = {
    path: {
      network: 'off', platform: 'windows',
      destination: { input: 'drive.google.com/upload', host: 'drive.google.com' },
      trace: { decrypted: true, hops: [
        { key: 'zcc', label: 'Client Connector app profile', status: 'pass', decided_by: { name: 'Default app profile' }, detail: 'No bypass for this host.' },
        { key: 'forwarding', label: 'Forwarding profile', status: 'pass', decided_by: { name: 'Z-Tunnel 2.0' }, detail: 'Off network: tunnel.' },
        { key: 'pac', label: 'PAC file', status: 'pass', decided_by: null, detail: 'No DIRECT statement matches.' },
        { key: 'cac', label: 'Cloud App Control', status: 'pass', decided_by: { name: 'Allow Google Drive' }, detail: 'Upload allowed.' },
        { key: 'url', label: 'URL filtering', status: 'pass', decided_by: { name: 'Allow file sharing' }, detail: 'Category File Sharing: allowed.' },
        { key: 'ssl', label: 'SSL inspection', status: 'pass', decided_by: { name: 'Decrypt all' }, detail: 'Decrypted.' },
        { key: 'ftc', label: 'File Type Control', status: 'none', decided_by: null, detail: 'No rule restricts .xlsx.' },
        { key: 'dlp', label: 'Web DLP', status: 'conditional', decided_by: null, detail: 'Three configured candidates; content simulation is separate.', rules: [
          { name: 'PCI – Block', action: 'BLOCK', enforcing: true, engines: ['PCI ENGINE'] },
          { name: 'PII – Monitor', action: 'ALLOW', enforcing: false, engines: ['PII ENGINE'] },
          { name: 'PHI – Block', action: 'BLOCK', enforcing: true, engines: ['PHI ENGINE'] }] },
      ] },
      verdict: { outcome: 'conditional', headline: 'Reference configuration for drive.google.com; no transaction observed.', summary: 'Three Web DLP rules see the content; whether they act depends on what is in it.' },
    },
    corpus: {
      corpus_length: 4210,
      results: [{ id: 63, name: 'PCI – Card numbers', total_hits: 3 }, { id: 64, name: 'PII – US SSN', total_hits: 2 }, { id: 65, name: 'PHI – Medical terms', total_hits: 0 }],
      predefined: [],
      engines: [
        { name: 'PCI ENGINE', expression: '(D63.S > 4)', fires: false, terms: ['D63.S > 4: 3 → false'], rules: ['PCI – Block'] },
        { name: 'PII ENGINE', expression: '(D64.S > 0)', fires: true, terms: ['D64.S > 0: 2 → true'], rules: ['PII – Monitor'] },
        { name: 'PHI ENGINE', expression: '(D65.S > 2)', fires: false, terms: ['D65.S > 2: 0 → false'], rules: ['PHI – Block'] },
      ],
    },
    deploy: {
      stage: 'plan', tenant_label: 'sample tenant', packs: ['Sample pack'],
      items: [
        { kind: 'dictionary', name: 'PCI – Card numbers', status: 'create', depends_on: ['predefined:CREDIT_CARDS'] },
        { kind: 'dictionary', name: 'PII – US SSN', status: 'create', depends_on: ['predefined:SSN'] },
        { kind: 'dictionary', name: 'PHI – Medical terms', status: 'reuse', depends_on: [] },
        { kind: 'engine', name: 'PCI engine', status: 'create', depends_on: ['dictionary:PCI – Card numbers'] },
        { kind: 'engine', name: 'PII engine', status: 'create', depends_on: ['dictionary:PII – US SSN'] },
        { kind: 'engine', name: 'PHI engine', status: 'create', depends_on: ['dictionary:PHI – Medical terms'] },
        { kind: 'policy', name: 'Web – PCI (monitor)', status: 'create', depends_on: ['engine:PCI engine'] },
        { kind: 'policy', name: 'Endpoint – PII (monitor)', status: 'create', depends_on: ['engine:PII engine'] },
        { kind: 'policy', name: 'SaaS – PHI (monitor)', status: 'create', depends_on: ['engine:PHI engine', 'missing:SaaS tenant'] },
        { kind: 'policy', name: 'Email – PCI and PII (monitor)', status: 'create', depends_on: ['engine:PCI engine', 'engine:PII engine'] },
      ],
    },
    incidents: [
      { id: 's1', channel: 'web', rules: ['PCI – Block'], engines: ['PCI engine'], dictionaries: [{ name: 'Credit cards', count: 14 }], enforcement: 'enforced', host: 'drive.google.com' },
      { id: 's2', channel: 'endpoint', rules: ['Endpoint – PII'], engines: ['PII engine'], dictionaries: [{ name: 'US SSN', count: 3 }], enforcement: 'monitor', host: 'USB drive' },
      { id: 's3', channel: 'email', rules: ['Email – PCI'], engines: ['PCI engine'], dictionaries: [{ name: 'Credit cards', count: 6 }], enforcement: 'monitor', host: 'partner.example' },
      { id: 's4', channel: 'saas', rules: ['SaaS – PHI'], engines: ['PHI engine'], dictionaries: [{ name: 'Medical terms', count: 9 }], enforcement: 'enforced', host: 'SharePoint' },
    ],
  };

  const FA = {
    pathModel, parseTerm, corpusModel, pathDrillModel, deployModel, liveModel, drillSummary, hopTone,
    ARCH, SAMPLE, hopPlayer, drill, graph, live, steps, E,
    dataFlowModel, dfRoute, sslWalkModel, sslCoverageModel, river, streams, ruleWalk, playButton, altList,
  };
  root.FA = FA;
  if (typeof module !== 'undefined' && module.exports) module.exports = FA;
})(typeof window !== 'undefined' ? window : globalThis);
