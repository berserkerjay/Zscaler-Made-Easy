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
  const OUTCOME_TONE = { blocked: 'bad', bypassed: 'bad', blind: 'warn', monitor: 'warn', none: 'warn', unknown: 'warn', out_of_scope: 'warn', enforce: 'ok',
    zpa_allowed: 'ok', zpa_denied: 'bad', zpa_conditional: 'warn' };

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

  // ── Traffic path: every step a Path analyzer result walks ─────────
  // The device (or a workload) → Client Connector (or the Cloud or Branch
  // Connector) → ZPA, which turns the traffic to the App Connectors and the
  // private app when it carries it → the PAC file (evaluated, never run) →
  // the Zero Trust Exchange → every ZIA module in order, SSL inspection
  // where it decides what the later modules see → the destination. One
  // node per step with its verdict, its deciding rule and the card it
  // opens; `stop` is the step that decides, marked (block, drop, isolate,
  // caution, bypass, or "not assessed"); a conditional step has a fork.
  const TP_SHORT = { atp: 'Threat protection', firewall: 'Cloud Firewall', dns: 'DNS Control', cac: 'Cloud App Control', url: 'URL filtering',
    ssl: 'SSL inspection', sandbox: 'Sandbox', ftc: 'File Type Control', dlp: 'Web DLP', fwdctl: 'Forwarding control' };
  const TP_WORD = {
    allow: 'allows it', block: 'blocks it', caution: 'shows a caution page', isolate: 'isolates it', redirect: 'redirects it', inspect: 'inspects it',
    decrypt: 'decrypts it', no_decrypt: 'leaves it encrypted', none: 'no rule applies', blind: 'cannot see it', skipped: 'skipped',
    conditional: 'depends on conditions', unknown: 'unknown', not_applicable: 'not applicable', not_reached: 'not reached', out_of_scope: 'not in scope',
    matched: 'matches', not_matched: 'no match', intercepted: 'intercepts it', bypassed: 'bypasses', forwarded: 'forwards it', dropped: 'drops it', carried: 'carries it',
  };
  const TP_NET = { off: 'off network', on: 'trusted network', vpn: 'VPN' };
  const TP_HOP = { pass: 'allow', warn: 'conditional', bypass: 'bypassed', blocked: 'block', unknown: 'unknown', out_of_scope: 'out_of_scope', na: 'not_applicable',
    not_reached: 'not_reached', conditional: 'conditional', none: 'none', error: 'unknown' };
  // The marker where the traffic stops, and its words.
  const TP_MARK = { block: '■', drop: '✕', isolate: '▣', caution: '!', bypass: '↷', unknown: '?' };
  const TP_MARK_WORD = { block: 'blocked', drop: 'dropped', isolate: 'isolated', caution: 'caution', bypass: 'bypassed', unknown: 'not assessed' };
  function tpTone(v) {
    if (v === 'block' || v === 'dropped') return 'stop';
    if (['isolate', 'caution', 'redirect', 'conditional', 'unknown', 'no_decrypt', 'blind', 'bypassed'].indexOf(v) >= 0) return 'warn';
    if (['allow', 'inspect', 'decrypt', 'matched', 'forwarded', 'intercepted', 'carried'].indexOf(v) >= 0) return 'pass';
    if (v === 'not_reached') return 'after';
    if (v === 'not_applicable' || v === 'out_of_scope' || v === 'skipped') return 'na';
    return 'idle';
  }
  function tpNode(key, label, verdict, extra) {
    const x = extra || {};
    const word = x.word || TP_WORD[verdict] || String(verdict || '').replace(/_/g, ' ');
    return { key, label, verdict: verdict || 'unknown', tone: x.tone || tpTone(verdict), word, rule: x.rule || '', sub: clip(x.sub || x.rule || word, 32),
      note: clip(x.note || '', 280), anchor: x.anchor || null, mark: x.mark || null, fork: x.fork || null, lane: x.lane || 'main' };
  }
  const tpRule = m => (m && m.rule && m.rule.name) || '';
  const tpNote = m => (m ? String(m.detail || (m.notes || [])[0] || '') : '');
  // "TCP/443 (HTTPS (web))": what the ZIA modules traced, else the port.
  function tpTraffic(res, z) {
    if (z && z.traffic && z.traffic.label) return String(z.traffic.label);
    const vt = res.verdict && res.verdict.traffic;
    if (vt && vt.label) return String(vt.label);
    const d = res.destination || {};
    const port = d.port || (d.scheme === 'http' ? 80 : 443);
    return `${String(d.protocol || 'tcp').toUpperCase()}/${port}`;
  }
  const TP_REFERENCE = [
    ['device', 'Device', 'the user starts it'], ['zcc', 'Client Connector', 'app and forwarding profile'], ['zpa', 'ZPA', 'private apps turn here'],
    ['pac', 'PAC file', 'evaluated, never run'], ['zte', 'Zero Trust Exchange', 'ZIA receives it'], ['atp', 'Threat protection', 'threat categories'],
    ['firewall', 'Cloud Firewall', 'every port and protocol'], ['dns', 'DNS Control', 'the name lookup'], ['cac', 'Cloud App Control', 'the cloud app'],
    ['url', 'URL filtering', 'the URL category'], ['ssl', 'SSL inspection', 'decides what is seen'], ['sandbox', 'Sandbox', 'unknown files'],
    ['ftc', 'File Type Control', 'the file type'], ['dlp', 'Web DLP', 'the content'], ['fwdctl', 'Forwarding control', 'how ZIA sends it on'],
    ['dest', 'Destination', 'the internet'],
  ];
  function tpReference() {
    const nodes = TP_REFERENCE.map(r => tpNode(r[0], r[1], 'none', { sub: r[2], word: r[2], tone: 'idle' }));
    return { mode: 'reference', nodes, stop: -1, dest: '', traffic: 'Any traffic', identity: '', source: 'device', verdict: { tone: '', outcome: '', text: '' },
      summary: ['The reference path, idling: no destination analyzed yet. Traffic leaves the device through Client Connector; ZPA takes private applications to the App Connectors; the PAC file (evaluated, never run) and the forwarding profile send the rest to the Zero Trust Exchange, where every ZIA module applies in order: Advanced Threat Protection, Cloud Firewall, DNS Control, Cloud App Control, URL filtering, SSL inspection (which decides what the later modules see), Sandbox, File Type Control and Web DLP, then Forwarding control (how ZIA sends it on) and the destination.'] };
  }

  // Path analyzer result → {mode, nodes, stop, traffic, identity, verdict, summary}.
  function trafficPathModel(res) {
    if (!res || !(res.trace || res.modules || res.zia_modules)) return tpReference();
    const mods = Array.isArray(res.modules) ? res.modules.filter(m => m && typeof m === 'object') : [];
    const z = res.zia_modules && Array.isArray(res.zia_modules.modules) ? res.zia_modules : null;
    const t = res.trace || {}, v = res.verdict || {};
    const hops = Array.isArray(t.hops) ? t.hops.filter(Boolean) : [];
    const mod = k => mods.filter(m => m.key === k)[0] || null;
    const hop = k => hops.filter(h => h.key === k)[0] || null;
    const workload = res.source === 'workload';
    const outcome = String(v.outcome || t.outcome || '');
    const ziaApplies = res.zia_applies !== false;
    const zm = mods.filter(m => m.key === 'zpa' || String(m.key || '').indexOf('zpa_') === 0);
    // ZPA carries it only when the result is ZPA's own (a zpa_* outcome).
    const zpaCarries = /^zpa_/.test(outcome) && zm.length > 0;
    const nodes = [];
    // 1. Where it starts.
    if (workload) {
      const wg = mod('workload_groups');
      nodes.push(tpNode('workload', 'Workload', 'allow', { tone: 'pass', word: 'starts it', anchor: { module: 'workload_groups', hop: 'workload' },
        sub: !wg ? 'source' : wg.verdict === 'matched' ? 'in a workload group' : wg.verdict === 'not_matched' ? 'in no workload group' : 'group unknown', note: tpNote(wg) }));
    } else {
      nodes.push(tpNode('device', 'Device', 'allow', { tone: 'pass', word: 'starts it', anchor: { id: 'paHeadline' }, sub: [res.platform || t.platform, TP_NET[res.network || t.network] || ''].filter(Boolean).join(' · '),
        note: 'The user\'s device starts the transaction.' }));
    }
    // 2. What forwards it.
    if (workload) {
      const cf = mod('connector_forwarding'), vv = cf ? cf.verdict : 'unknown';
      nodes.push(tpNode('connector', 'Cloud or Branch Connector', vv, { rule: tpRule(cf), note: (cf && (cf.notes || [])[0]) || tpNote(cf), anchor: { module: 'connector_forwarding', hop: 'connector' },
        mark: vv === 'dropped' ? 'drop' : vv === 'bypassed' ? 'bypass' : null, fork: vv === 'conditional' ? { text: 'an earlier rule may send it elsewhere' } : null }));
    } else {
      const zh = hop('zcc'), fh = hop('forwarding'), st = [zh && zh.status, fh && fh.status];
      let vv, weak = false;
      if (st.indexOf('bypass') >= 0) vv = 'bypassed';
      else if (st.indexOf('blocked') >= 0) vv = 'block';
      else if (!zh && !fh) vv = zpaCarries ? 'intercepted' : 'out_of_scope';
      else if (st.every(s => !s || s === 'out_of_scope')) vv = 'out_of_scope';
      else if (st.indexOf('unknown') >= 0) vv = 'unknown';
      else if (st.indexOf('conditional') >= 0) vv = 'conditional';
      else { vv = 'intercepted'; weak = st.indexOf('warn') >= 0; }
      const by = (fh && fh.decided_by && fh.decided_by.name) || (zh && zh.decided_by && zh.decided_by.name) || '';
      nodes.push(tpNode('zcc', 'Client Connector', vv, { rule: by, sub: !zh && !fh && zpaCarries ? 'sends it to ZPA' : '', anchor: { hop: 'zcc' },
        tone: weak ? 'warn' : undefined, word: weak ? 'intercepts it, with a weak point' : undefined,
        note: [zh && zh.detail, fh && fh.detail].filter(Boolean).join(' ') || (vv === 'out_of_scope' ? 'Client Connector is not in scope on the Scope page; reaching Zscaler is assumed.' : ''),
        mark: vv === 'bypassed' ? 'bypass' : vv === 'block' ? 'block' : null, fork: vv === 'conditional' ? { text: 'depends on the device' } : null }));
    }
    // Where it goes after that: ZPA, ZIA, nowhere (sent direct or dropped
    // by the connector), or a part not assessed (not in scope).
    const connVerdict = workload ? nodes[1].verdict : '';
    let route = 'zia';
    if (zpaCarries) route = 'zpa';
    else if (ziaApplies) route = 'zia';
    else if (workload && (connVerdict === 'bypassed' || connVerdict === 'dropped')) route = 'none';
    else if (workload && !zm.length && hop('zpa_segment')) route = 'zpa_unassessed';
    else route = 'zia_unassessed';
    // 3. ZPA: first for a device; for a workload when the connector sends it there.
    if (zm.length || !workload || route === 'zpa_unassessed') {
      const seg = mod('zpa_segment'), acc = mod('zpa_access'), whole = mod('zpa');
      const cond = zm.some(m => m.verdict === 'conditional');
      const x = { anchor: { module: acc && acc.verdict !== 'not_reached' && (zpaCarries || cond) ? 'zpa_access' : seg ? 'zpa_segment' : 'zpa', hop: 'zpa_segment' } };
      let vv;
      if (!zm.length) {
        vv = 'out_of_scope';
        x.note = 'ZPA is not in scope on the Scope page, so whether ZPA carries this destination was not assessed.';
        if (route === 'zpa_unassessed') { x.mark = 'unknown'; x.note = String(v.headline || x.note); }
      } else if (whole) {
        vv = whole.verdict; x.note = tpNote(whole);
        if (route === 'zpa_unassessed') x.mark = 'unknown';
      } else if (zpaCarries) {
        x.note = String(v.headline || tpNote(acc));
        if (outcome === 'zpa_denied') { vv = 'block'; x.mark = 'block'; x.rule = tpRule(acc) || 'default deny'; }
        else if (outcome === 'out_of_scope' || outcome === 'not_read') { vv = 'unknown'; x.mark = 'unknown'; }
        else {
          vv = cond ? 'conditional' : 'carried'; x.rule = tpRule(acc); x.word = cond ? 'carries it; access depends on conditions' : 'carries it';
          if (cond) x.fork = { text: 'access may be denied' };
        }
        x.sub = x.rule || tpRule(seg);
      } else if (cond) {
        vv = 'conditional'; x.fork = { text: 'may carry it to the app' }; x.word = 'may carry it'; x.sub = tpRule(seg);
        x.note = zm.filter(m => m.verdict === 'conditional').map(tpNote).filter(Boolean).join(' ');
      } else {
        const none = !seg || seg.verdict === 'not_matched';
        vv = none ? 'not_matched' : 'bypassed'; x.tone = 'idle';
        x.word = none ? 'does not carry it: no segment matches' : 'does not carry it: it goes outside ZPA';
        x.sub = none ? 'no segment matches' : 'goes outside ZPA';
        x.note = zm.map(tpNote).filter(Boolean).slice(0, 2).join(' ');
      }
      nodes.push(tpNode('zpa', 'ZPA', vv, x));
    }
    const dest = destText(res.destination) || destText(t.destination);
    if (route === 'zpa') {
      // ZPA carries it: the traffic turns to the App Connectors and the app.
      const conn = mod('zpa_connectors'), zp = nodes[nodes.length - 1];
      if (!zp.mark) {
        if (!zp.fork) zp.fork = { text: 'ZIA path not taken', ghost: true };
        if (conn) nodes.push(tpNode('zpa_connectors', 'App Connectors', conn.verdict, { lane: 'zpa', anchor: { module: 'zpa_connectors', hop: 'zpa_connectors' },
          sub: conn.verdict === 'block' ? 'none connected' : conn.verdict === 'allow' ? 'connected' : 'unknown', word: conn.verdict === 'block' ? 'none is connected' : conn.verdict === 'allow' ? 'connected' : 'unknown',
          note: (conn.notes || []).join(' '), mark: conn.verdict === 'block' ? 'block' : null }));
      }
      nodes.push(tpNode('dest', 'Private app', 'allow', { lane: 'zpa', sub: dest, word: 'reached through ZPA', note: 'ZPA carries the traffic to the application: ZIA does not apply.' }));
    } else if (route === 'none' || route === 'zpa_unassessed') {
      nodes.push(tpNode('dest', 'Destination', 'allow', { sub: dest, word: 'reached', note: String(v.headline || '') }));
    } else {
      // 4. The PAC file (a device's browser traffic).
      if (!workload) {
        const pm = mod('pac'), ph = hop('pac');
        const vv = pm ? pm.verdict : ph ? (TP_HOP[ph.status] || 'unknown') : 'not_applicable';
        nodes.push(tpNode('pac', 'PAC file', vv, { rule: tpRule(pm), anchor: { module: 'pac', hop: 'pac' }, note: (ph && ph.detail) || tpNote(pm) || 'No PAC file is on this path.',
          word: vv === 'forwarded' ? 'sends it to Zscaler' : vv === 'bypassed' ? 'returns DIRECT: around Zscaler' : vv === 'not_applicable' ? 'not used' : undefined,
          mark: vv === 'bypassed' ? 'bypass' : null, fork: vv === 'conditional' ? { text: 'may go direct' } : null }));
      }
      // 5. The Zero Trust Exchange and every ZIA module in order.
      if (route === 'zia_unassessed') {
        nodes.push(tpNode('zte', 'Zero Trust Exchange', 'out_of_scope', { sub: 'ZIA not assessed', word: 'receives it; ZIA policy is not assessed', note: String(v.headline || ''), mark: 'unknown' }));
      } else if (!z) {
        // A result without the module list (older, or a sample): the
        // trace's own ZIA hops, in their order.
        nodes.push(tpNode('zte', 'Zero Trust Exchange', 'forwarded', { sub: 'ZIA receives it', word: 'receives it' }));
        hops.filter(h => TP_SHORT[h.key]).forEach(h => {
          const vv = TP_HOP[h.status] || 'unknown';
          nodes.push(tpNode(h.key, TP_SHORT[h.key], vv, { rule: (h.decided_by && h.decided_by.name) || '', note: h.detail || '', anchor: { hop: h.key },
            mark: vv === 'block' ? 'block' : null, fork: vv === 'conditional' ? { text: 'depends on conditions' } : null }));
        });
      } else {
        nodes.push(tpNode('zte', 'Zero Trust Exchange', 'forwarded', { sub: 'ZIA receives it', word: 'receives it', anchor: { id: 'pmZiaH' },
          note: 'ZIA\'s modules apply in order; SSL inspection decides what the later ones can see.' }));
        const list = z.modules.filter(m => m && typeof m === 'object').slice();
        if (z.modifier && typeof z.modifier === 'object') {
          let at = -1;
          list.forEach((m, i) => { if (at < 0 && ['sandbox', 'ftc', 'dlp'].indexOf(m.key) >= 0) at = i; });
          list.splice(at < 0 ? list.length : at, 0, Object.assign({}, z.modifier, { key: z.modifier.key || 'ssl' }));
        }
        list.forEach(m => {
          const vv = m.verdict, definite = m.certainty !== 'conditional';
          let mark = null, fork = null;
          if (z.stops_at && m.key === z.stops_at) mark = 'block';
          else if ((vv === 'isolate' || vv === 'caution') && definite) mark = vv;
          if (!mark && (!definite || vv === 'conditional')) fork = { text: vv === 'block' ? 'may block' : vv === 'isolate' ? 'may isolate' : vv === 'caution' ? 'may caution' : 'depends on conditions' };
          nodes.push(tpNode(m.key, TP_SHORT[m.key] || m.module || m.key, vv, { rule: tpRule(m), note: tpNote(m), anchor: { module: m.key, hop: m.key }, mark, fork,
            tone: fork && vv === 'block' ? 'warn' : undefined, word: fork && vv === 'block' ? 'may block it' : undefined }));
        });
      }
      nodes.push(tpNode('dest', 'Destination', 'allow', { sub: dest, word: 'reached', note: String(v.headline || '') }));
    }
    // Where it stops; nothing after it is reached (bypassed traffic still
    // reaches the destination, around Zscaler; a part not assessed leaves
    // the end open).
    let stop = -1;
    nodes.forEach((n, i) => { if (stop < 0 && n.mark) stop = i; });
    const last = nodes[nodes.length - 1];
    if (stop >= 0) {
      const m = nodes[stop].mark;
      for (let i = stop + 1; i < nodes.length - 1; i++) Object.assign(nodes[i], { tone: 'after', word: 'not reached', sub: 'not reached', rule: '', fork: null });
      if (m === 'bypass') Object.assign(last, { tone: 'warn', word: 'reached around Zscaler, not inspected' });
      else if (m === 'unknown') Object.assign(last, { tone: 'warn', word: 'not established' });
      else Object.assign(last, { tone: 'after', word: 'never reached' });
    } else if (v.certainty === 'conditional' || nodes.some(n => n.fork && !n.fork.ghost)) {
      Object.assign(last, { tone: 'warn', word: 'reached, unless a condition changes it' });
    }
    const traffic = tpTraffic(res, z);
    const w = res.whatif;
    const identity = w && w.identity_label ? String(w.identity_label) : '';
    const from = workload ? 'a workload' : `a device (${[res.platform || t.platform, TP_NET[res.network || t.network] || ''].filter(Boolean).join(', ')})`;
    const summary = [`${traffic} from ${from} to ${dest || 'the destination'}${identity ? `, evaluated for ${identity} (what-if)` : ', for any user'}.`];
    nodes.forEach((n, i) => summary.push(`${i + 1}. ${n.label}: ${n.word}${n.rule ? ` (rule ${n.rule})` : ''}${i === stop ? `; ${TP_MARK_WORD[n.mark]} here` : ''}${n.fork && n.word.indexOf(n.fork.text) < 0 ? `; ${n.fork.text}` : ''}.${n.note ? ' ' + n.note : ''}`));
    if (v.headline) summary.push(`Verdict: ${v.headline}`);
    // What-if: the identity evaluated and the conditions the action still depends on.
    const deps = (w && Array.isArray(w.depends_on) ? w.depends_on : []).filter(d => d && typeof d === 'object');
    const depends = deps.slice(0, 5).map(d => `${d.section || d.module || 'A rule'}: rule ${(d.rule && d.rule.name) || 'unnamed'} would give ${d.action || d.verdict || 'another action'}${d.otherwise ? `, otherwise ${d.otherwise}` : ''}`);
    if (depends.length) summary.push(`Policy action also depends on: ${depends.join('; ')}${deps.length > 5 ? `; and ${deps.length - 5} more` : ''}.`);
    const whatif = { identity, depends, more: Math.max(0, deps.length - 5), counts: (w && w.counts) || null, empty: (w && w.empty_reason) || '' };
    return { mode: 'result', nodes, stop, dest, traffic, identity, whatif, source: workload ? 'workload' : 'device',
      verdict: { tone: OUTCOME_TONE[outcome] || (stop >= 0 ? 'bad' : 'warn'), outcome, text: [v.headline, v.summary].filter(Boolean).join(' ') || outcome }, summary };
  }

  // ── Test a list: where every row was decided ─────────────────────
  // The job's tally (bulk_test: {done, total, phase, results: {result: n},
  // at: {area: {result: n}}}) → one box per deciding place with its count.
  const LF_AREAS = [['client_connector', 'Client Connector'], ['zpa', 'ZPA'], ['atp', 'Threat protection'], ['firewall', 'Cloud Firewall'],
    ['dns', 'DNS Control'], ['cloud_app', 'Cloud App Control'], ['url', 'URL filtering']];
  const LF_DECIDING = ['blocked', 'bypassed', 'isolated', 'caution'];
  const LF_RESULTS = ['blocked', 'allowed', 'bypassed', 'isolated', 'caution', 'unverified'];
  function listFlowModel(p) {
    const at = (p && p.at && typeof p.at === 'object') ? p.at : {};
    const num = x => (typeof x === 'number' && isFinite(x) && x > 0 ? Math.floor(x) : 0);
    const cnt = (a, r) => num((at[a] || {})[r]);
    const words = (a, rs) => rs.filter(r => cnt(a, r)).map(r => `${cnt(a, r)} ${r}`).join(', ');
    const boxes = LF_AREAS.map(([key, label]) => {
      const rs = key === 'zpa' ? LF_RESULTS : LF_DECIDING;
      const n = rs.reduce((s, r) => s + cnt(key, r), 0);
      return { key, label, n, kinds: rs.filter(r => cnt(key, r)), word: words(key, rs) || (key === 'zpa' ? 'none carried' : 'none decided here') };
    });
    let allowed = 0, unverified = 0;
    Object.keys(at).forEach(a => {
      if (a === 'zpa') return;
      allowed += cnt(a, 'allowed');
      unverified += cnt(a, 'unverified');
      if (LF_AREAS.every(x => x[0] !== a)) unverified += LF_DECIDING.reduce((s, r) => s + cnt(a, r), 0);
    });
    boxes.push({ key: 'dest', label: 'Destination', n: allowed, word: `${allowed} allowed`, end: true });
    boxes.push({ key: 'unverified', label: 'Unverified', n: unverified, word: `${unverified} unverified`, end: true });
    const r = (p && p.results) || {};
    const totals = { zpa: boxes[1].n };
    LF_RESULTS.forEach(k => { totals[k] = num(r[k]); });
    return { boxes, totals, done: num(p && p.done), total: num(p && p.total), phase: String((p && p.phase) || '') };
  }
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
  // `force` plays it even under reduced motion (the viewer pressed Play).
  function fly(clock, svg, path, ms, cls, force) {
    return new Promise(done => {
      if ((reduced() && !force) || !path.getTotalLength) { done(); return; }
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
  // opts.sink: {title, sub} of the last box (default Workflow Automation).
  // setMotion(true | false | null): play the dots even under reduced
  // motion, land each incident at once (paused), or follow the system.
  function live(host, opts) {
    const o = opts || {};
    host.innerHTML = '';
    const clock = animator();
    let motion = null;
    const go = (p, ms, cls) => (motion === false ? Promise.resolve() : fly(clock, svg, p, ms, cls, motion === true));
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
    const wa = box(svg, 895, 127, 100, 46, (o.sink && o.sink.title) || 'Workflow', (o.sink && o.sink.sub) || 'Automation');
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
        await go(P['c' + c], 450, cls);
        cap[c].set(''); n[c]++; cap[c].sub(`${n[c]} incident${n[c] === 1 ? '' : 's'}`);
        dic.sub(m.dicts[0] ? clip(`${m.dicts[0].name}: ${m.dicts[0].count}`, 22) : 'match counts');
        await go(P.de, 300, cls);
        eng.sub(clip(m.engine || 'verdict', 20));
        await go(P['r' + c], 350, cls);
        rule[c].sub(clip(m.rule, 22)); rule[c].set(ok ? 'stop' : 'warn');
        await go(P[(ok ? 'e' : unknown ? 'u' : 'm') + c], 350, cls);
        n[ok ? 'enforced' : unknown ? 'unknown_action' : 'monitor']++; (ok ? enf : unknown ? unk : mon).sub(String(n[ok ? 'enforced' : unknown ? 'unknown_action' : 'monitor']));
        await go(ok ? P.ew : unknown ? P.uw : P.mw, 300, cls);
        rule[c].set('');
      }).catch(() => {});
      return queue;
    }
    return { push, counts: () => Object.assign({}, n), setMotion(v) { motion = v; }, idle: () => queue, destroy() { clock.destroy(); host.innerHTML = ''; } };
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

  // ── Traffic path player ──────────────────────────────────────────
  // model: trafficPathModel(). Packets travel the path node by node, each
  // box lights up with its verdict as a packet lands, and they stop at the
  // marked step. opts: loop (keep packets flowing once the path is drawn:
  // the live view), stepper (Back, Next, Restart and a speed: the replay),
  // onSelect(node) when a box is clicked or Enter is pressed on it. The
  // picture lays itself out for the width it has (one column on a phone),
  // so the page never scrolls sideways. Motion follows prefers-reduced-
  // motion (the final picture, with Play motion to start it anyway) and
  // stops while the tab is hidden; the steps are listed in words under it.
  let tpSeq = 0;
  function trafficPath(host, model, opts) {
    const o = opts || {};
    const id = 'tp' + (++tpSeq);
    const n = model.nodes.length, end = model.stop >= 0 ? model.stop : n - 1;
    const ref = model.mode === 'reference';
    const chips = [`<span class="tp-chip"><span class="k">Traffic</span> ${E(model.traffic)}</span>`];
    if (model.identity) chips.push(`<span class="tp-chip"><span class="k">What-if</span> ${E(model.identity)}</span>`);
    if (model.dest) chips.push(`<span class="tp-chip"><span class="k">To</span> ${E(model.dest)}</span>`);
    host.innerHTML = `<div class="tp-head">${chips.join('')}<span class="sep"></span>
        ${o.stepper ? '<button type="button" class="rp-btn tp-back">Back</button>' : ''}
        <button type="button" class="rp-btn tp-play" aria-controls="${id}-stage">Pause motion</button>
        ${o.stepper ? `<button type="button" class="rp-btn tp-next">Next</button><button type="button" class="rp-btn tp-restart">Restart</button>
        <label class="df-ctl tp-speed"><span class="lbl">Speed</span><select class="tp-speed-sel" aria-label="Animation speed"><option value="0.5">Slow</option><option value="1" selected>Normal</option><option value="2">Fast</option></select></label>` : ''}
      </div>
      <div class="tp-stage" id="${id}-stage"></div>
      <p class="df-hint tp-note" id="${id}-note" aria-live="polite"></p>
      <details class="tp-alt"${o.openSteps ? ' open' : ''}><summary>${ref ? 'The reference path in words' : `The path in words (${n} steps)`}</summary>
        <ol class="tp-steps" id="${id}-steps">${model.summary.slice(1, n + 1).length === n ? model.summary.slice(1, n + 1).map(s => `<li>${E(s.replace(/^\d+\.\s*/, ''))}</li>`).join('') : model.nodes.map(x => `<li>${E(x.label)}: ${E(x.word)}</li>`).join('')}</ol>
        ${model.summary.length ? `<p class="df-hint">${E(ref ? model.summary[0] : [model.summary[0]].concat(model.summary.slice(n + 1)).join(' '))}</p>` : ''}
      </details>`;
    const stageEl = host.querySelector('.tp-stage'), noteEl = host.querySelector('.tp-note'), stepsEl = host.querySelector('.tp-steps');
    const btn = host.querySelector('.tp-play');
    const clock = animator();
    let svg = null, boxes = [], edges = [], lens = [], tags = [], forks = [], dotsG = null, per = 0;
    let pos = ref ? end : 0, playing = false, chosen = null, speed = 1, gen = 0, frames = 0, packets = [], acc = 0, lastT = 0, streamOff = null, ro = null, dead = false;
    const want = () => (chosen != null ? chosen : !reduced());
    const dur = ms => ms / speed;
    function tick() { frames++; host.setAttribute('data-tp-frames', String(frames)); }

    // Layout: as many boxes a row as fit, rows snaking; one column on a phone.
    function build() {
      const avail = Math.max(260, Math.min(1200, Math.floor(stageEl.clientWidth || host.clientWidth || 1000)));
      const M = 18, GAP = 34, BH = 46, ROWH = BH + 48, TOP = 16;
      let p = Math.max(1, Math.floor((avail - 2 * M + GAP) / (150 + GAP)));
      p = Math.min(p, n);
      if (svg && p === per) return;
      per = p;
      const W = per === 1 ? avail : Math.max(avail, 2 * M + per * 150 + (per - 1) * GAP);
      const bw = per === 1 ? Math.min(W - 2 * M, 320) : Math.floor((W - 2 * M - (per - 1) * GAP) / per);
      const rows = Math.ceil(n / per);
      stageEl.innerHTML = '';
      svg = newSvg(stageEl, W, rows * ROWH + TOP, ref ? 'The reference path, idling' : `The path of ${model.traffic} to ${model.dest || 'the destination'}`);
      svg.setAttribute('role', 'group'); svg.setAttribute('class', 'fa-svg tp-svg'); svg.setAttribute('aria-describedby', id + '-steps');
      svg.removeAttribute('tabindex');
      const at = model.nodes.map((x, i) => {
        const r = Math.floor(i / per), c = i % per, col = r % 2 ? per - 1 - c : c;
        return { x: M + col * (bw + GAP), y: TOP + r * ROWH, w: bw, h: BH, r, col };
      });
      const edgesG = svgEl('g', { class: 'tp-edges' }, svg);
      edges = []; lens = [];
      for (let i = 0; i < n - 1; i++) {
        const a = at[i], b = at[i + 1], ya = a.y + BH / 2, yb = b.y + BH / 2;
        let d;
        if (per === 1) d = `M${a.x + 24} ${a.y + BH} L${b.x + 24} ${b.y}`;
        else if (a.r === b.r) d = a.r % 2 === 0 ? `M${a.x + bw} ${ya} L${b.x} ${yb}` : `M${a.x} ${ya} L${b.x + bw} ${yb}`;
        else if (a.col === per - 1) d = `M${a.x + bw} ${ya} H${a.x + bw + 12} V${yb} H${b.x + bw}`;
        else d = `M${a.x} ${ya} H${a.x - 12} V${yb} H${b.x}`;
        const e = svgEl('path', { d, class: 'fa-edge' }, edgesG);
        edges.push(e);
        lens.push(e.getTotalLength ? e.getTotalLength() : 1);
      }
      forks = []; tags = [];
      boxes = model.nodes.map((x, i) => {
        const p0 = at[i];
        const b = box(svg, p0.x, p0.y, bw, BH, x.label, x.sub);
        if (x.fork) {
          const fx = p0.x + bw - 28, f = svgEl('g', { class: 'tp-fork' + (x.fork.ghost ? ' ghost' : '') }, svg);
          svgEl('path', { d: `M${fx} ${p0.y + BH} q2 10 12 14`, class: 'tp-fork-l' }, f);
          const ft = svgEl('text', { x: p0.x + bw, y: p0.y + BH + 27, 'text-anchor': 'end', class: 'tp-fork-t' }, f);
          ft.textContent = clip(x.fork.text, Math.floor((bw - 4) / 5.6));
          forks[i] = f;
        }
        if (x.mark) {
          const g = svgEl('g', { class: 'tp-tag mk-' + x.mark }, svg);
          const tt = svgEl('text', { x: p0.x + bw - 2, y: p0.y - 4, 'text-anchor': 'end' }, g);
          tt.textContent = `${TP_MARK[x.mark]} ${TP_MARK_WORD[x.mark]}`;
          tags[i] = g;
        }
        if (o.onSelect && !ref) {
          b.g.setAttribute('tabindex', '0'); b.g.setAttribute('role', 'button');
          b.g.setAttribute('aria-label', `${i + 1}. ${x.label}: ${x.word}${x.rule ? `, rule ${x.rule}` : ''}${x.mark && i === model.stop ? `, ${TP_MARK_WORD[x.mark]} here` : ''}. Opens its card.`);
          b.g.addEventListener('click', () => o.onSelect(x, i));
          b.g.addEventListener('keydown', ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); o.onSelect(x, i); } });
        }
        if (x.lane === 'zpa') b.g.classList.add('tp-zpa');
        return b;
      });
      dotsG = svgEl('g', { class: 'tp-dots' }, svg);
      packets = [];
      paint();
    }
    // The picture for `pos`: what has been reached shows its verdict.
    function paint() {
      boxes.forEach((b, i) => {
        const x = model.nodes[i];
        const shown = ref || i <= pos || (pos >= end && i > end);
        b.set(['tp-box', ref ? 'idle' : shown ? x.tone : 'pend', i === pos && !ref && playing && pos < end ? 'on' : ''].filter(Boolean).join(' '));
        if (x.lane === 'zpa') b.g.classList.add('tp-zpa');
        if (tags[i]) tags[i].setAttribute('display', pos >= i ? 'inline' : 'none');
        if (forks[i]) forks[i].setAttribute('display', ref || pos >= i ? 'inline' : 'none');
      });
      edges.forEach((e, i) => e.setAttribute('class', 'fa-edge' + (ref ? '' : i < pos ? ' lit' : (pos >= end && i >= end && model.stop >= 0 && model.nodes[model.stop].mark !== 'unknown') ? ' dead' : '')));
      Array.prototype.forEach.call(stepsEl.children, (li, i) => li.classList.toggle('cur', !ref && i === pos));
    }
    function say(i) {
      const x = model.nodes[i];
      noteEl.textContent = `Step ${i + 1} of ${n}: ${x.label}, ${x.word}${x.rule ? ` (rule ${x.rule})` : ''}.${i === model.stop ? ` ${TP_MARK_WORD[x.mark][0].toUpperCase()}${TP_MARK_WORD[x.mark].slice(1)} here.` : ''}${x.note ? ' ' + x.note : ''}`;
    }
    function setBtn() { btn.textContent = playing ? 'Pause motion' : 'Play motion'; }
    const CALM = 'Motion is off because your system asks for reduced motion: the picture shows where the traffic goes and where it stops. Play motion starts it anyway.';
    // One dot along edge i; resolves when it lands.
    function flyEdge(i, ms, cls) {
      return new Promise(done => {
        const e = edges[i];
        if (!want() || !e || !e.getTotalLength) { done(); return; }
        const dot = svgEl('circle', { r: 5, class: 'fa-dot tp-pkt' + (cls ? ' ' + cls : '') }, dotsG);
        let t0 = null;
        const stop = clock.add(now => {
          tick();
          if (t0 === null) t0 = now;
          const k = Math.min(1, (now - t0) / ms), q = e.getPointAtLength(lens[i] * k);
          dot.setAttribute('cx', q.x); dot.setAttribute('cy', q.y);
          if (k >= 1) { stop(); dot.remove(); done(); }
        });
      });
    }
    // A pause on the animation clock (so it stops while the tab is hidden).
    function clockWait(ms) {
      return new Promise(done => {
        if (!want()) { done(); return; }
        let t0 = null;
        const off = clock.add(now => { tick(); if (t0 === null) t0 = now; if (now - t0 >= ms) { off(); done(); } });
      });
    }
    // The live stream once the path is drawn: a packet every 1.5 s runs
    // to the stop and pops there with the stop's tone.
    function streamTick(now) {
      tick();
      const dt = lastT ? Math.min(50, now - lastT) : 16; lastT = now;
      acc += dt * speed;
      if (acc >= 1500 && packets.length < 8 && end > 0) {
        acc = 0;
        packets.push({ seg: 0, k: 0, el: svgEl('circle', { r: 4.5, class: 'fa-dot tp-pkt' + (model.stop >= 0 ? ' mk-' + model.nodes[model.stop].mark : '') }, dotsG) });
      }
      packets = packets.filter(pk => {
        pk.k += dt * speed / 520;
        while (pk.k >= 1 && pk.seg < end) { pk.k -= 1; pk.seg++; }
        if (pk.seg >= end) { pk.el.setAttribute('class', pk.el.getAttribute('class') + ' pop'); setTimeout(() => pk.el.remove(), 420); return false; }
        const q = edges[pk.seg].getPointAtLength(lens[pk.seg] * pk.k);
        pk.el.setAttribute('cx', q.x.toFixed(1)); pk.el.setAttribute('cy', q.y.toFixed(1));
        return true;
      });
    }
    function startStream() { if (streamOff || dead || !want() || !o.loop) return; lastT = 0; acc = 1500; streamOff = clock.add(streamTick); }
    function halt() {
      gen++; playing = false;
      if (streamOff) { streamOff(); streamOff = null; }
      clock.clear();
      if (dotsG) dotsG.innerHTML = '';
      packets = [];
    }
    function finished() {
      playing = !!(o.loop && want());
      paint(); setBtn();
      if (!ref) say(end);
      if (o.onDone) o.onDone();
      startStream();
    }
    async function play() {
      if (dead) return;
      halt(); playing = true; setBtn();
      if (pos >= end && !o.loop) pos = 0;
      const my = gen;
      paint();
      if (!want()) { pos = end; finished(); return; }
      while (my === gen && pos < end) {
        await flyEdge(pos, dur(560));
        if (my !== gen) return;
        pos++; paint();
        if (o.onStep) o.onStep(model.nodes[pos], pos);
        if (pos < end) await clockWait(dur(140));
      }
      if (my === gen) finished();
    }
    function pause() { halt(); paint(); setBtn(); }
    function step(dir) {
      halt();
      const was = pos;
      pos = Math.max(0, Math.min(end, pos + dir));
      paint(); setBtn(); say(pos);
      if (dir > 0 && pos > was) flyEdge(was, dur(420));
    }
    btn.addEventListener('click', () => { if (playing) { chosen = false; pause(); } else { chosen = true; play(); } });
    if (o.stepper) {
      host.querySelector('.tp-back').addEventListener('click', () => step(-1));
      host.querySelector('.tp-next').addEventListener('click', () => step(1));
      host.querySelector('.tp-restart').addEventListener('click', () => { halt(); pos = 0; paint(); play(); });
      host.querySelector('.tp-speed-sel').addEventListener('change', ev => { speed = Number(ev.target.value) || 1; });
    }
    build();
    if (root.ResizeObserver) {
      let w = stageEl.clientWidth;
      ro = new root.ResizeObserver(() => { if (Math.abs(stageEl.clientWidth - w) < 8) return; w = stageEl.clientWidth; const keep = playing; halt(); build(); if (keep) play(); });
      ro.observe(stageEl);
    }
    if (ref) { playing = want(); setBtn(); paint(); if (playing) { acc = 1500; startStream(); } }
    else if (want()) play();
    else { pos = end; paint(); setBtn(); say(end); noteEl.textContent = CALM + ' ' + noteEl.textContent; }
    if (ref && !want()) noteEl.textContent = CALM;
    return {
      play() { chosen = true; play(); }, pause() { chosen = false; pause(); }, step, playing: () => playing, frames: () => frames, pos: () => pos,
      destroy() { dead = true; halt(); clock.destroy(); if (ro) ro.disconnect(); host.innerHTML = ''; host.removeAttribute('data-tp-frames'); },
    };
  }

  // ── Test a list: rows streaming to the step that decides them ────
  // update(tally) with the job's tally (listFlowModel): each box's count
  // climbs to its new value and a few packets fly from the list to every
  // box that gained rows. Reduced motion: the counts change at once.
  function listFlow(host) {
    host.innerHTML = `<div class="tp-head lf-head"><span class="tp-chip lf-tot" aria-hidden="true"></span><span class="sep"></span><button type="button" class="rp-btn lf-play">Pause motion</button></div>
      <div class="tp-stage lf-stage"></div>
      <ul class="lf-alt df-hint" aria-label="Where the rows were decided"></ul>`;
    const stageEl = host.querySelector('.lf-stage'), alt = host.querySelector('.lf-alt'), tot = host.querySelector('.lf-tot'), btn = host.querySelector('.lf-play');
    const clock = animator();
    let chosen = null, frames = 0, svg = null, src = null, B = {}, P = {}, model = listFlowModel(null), shown = {}, dotsG = null, wide = null;
    const want = () => (chosen != null ? chosen : !reduced());
    model.boxes.forEach(b => { shown[b.key] = 0; });
    function vcurve(a, b) {
      const x1 = a.x + a.w / 2, y1 = a.y + a.h, x2 = b.x + b.w / 2, y2 = b.y, m = (y1 + y2) / 2;
      return svgEl('path', { d: `M${x1} ${y1} C${x1} ${m} ${x2} ${m} ${x2} ${y2}`, class: 'fa-edge' }, svg.querySelector('.lf-edges'));
    }
    function build() {
      const avail = Math.max(260, Math.min(1100, Math.floor(stageEl.clientWidth || host.clientWidth || 1000)));
      const isWide = avail >= 620;
      if (svg && isWide === wide) return;
      wide = isWide;
      stageEl.innerHTML = '';
      const list = model.boxes.filter(b => !b.end), ends = model.boxes.filter(b => b.end);
      let W, H;
      const pos = {};
      if (wide) {
        W = avail; H = list.length * 54 + 16;
        const cx = Math.round(W / 2 - 95);
        list.forEach((b, i) => { pos[b.key] = { x: cx, y: 8 + i * 54, w: 190, h: 44 }; });
        ends.forEach((b, i) => { pos[b.key] = { x: W - 18 - 170, y: Math.round(H / 2 - 70 + i * 96), w: 170, h: 44 }; });
        pos.src = { x: 18, y: Math.round(H / 2 - 22), w: 150, h: 44 };
      } else {
        W = avail;
        const bw = Math.floor((W - 36 - 12) / 2), all = list.concat(ends);
        H = 70 + Math.ceil(all.length / 2) * 54 + 8;
        pos.src = { x: 18, y: 8, w: W - 36, h: 44 };
        all.forEach((b, i) => { pos[b.key] = { x: 18 + (i % 2) * (bw + 12), y: 70 + Math.floor(i / 2) * 54, w: bw, h: 44 }; });
      }
      svg = newSvg(stageEl, W, H, 'The tested list, each row flowing to the step that decided it');
      svg.setAttribute('role', 'img'); svg.setAttribute('class', 'fa-svg tp-svg'); svg.removeAttribute('tabindex');
      svgEl('g', { class: 'lf-edges' }, svg);
      src = box(svg, pos.src.x, pos.src.y, pos.src.w, pos.src.h, 'Your list', '');
      P = {}; B = {};
      model.boxes.forEach(b => {
        P[b.key] = wide ? curve(svg.querySelector('.lf-edges'), pos.src, pos[b.key]) : vcurve(pos.src, pos[b.key]);
        B[b.key] = box(svg, pos[b.key].x, pos[b.key].y, pos[b.key].w, pos[b.key].h, b.label, '');
      });
      dotsG = svgEl('g', { class: 'tp-dots' }, svg);
      draw();
    }
    const TONE = { client_connector: 'warn', zpa: 'pass', dest: 'pass', unverified: 'warn' };
    function draw() {
      model.boxes.forEach(b => {
        const v = Math.round(shown[b.key] || 0);
        B[b.key].sub(b.key === 'dest' ? `${v} allowed` : b.key === 'unverified' ? `${v} unverified` : !v ? b.word : b.kinds.length === 1 ? `${v} ${b.kinds[0]}` : `${v} rows: ${b.word}`);
        B[b.key].set(v ? (TONE[b.key] || 'stop') : '');
        P[b.key].setAttribute('class', 'fa-edge' + (v ? ' lit' : ''));
      });
      const t = model.totals;
      src.sub(model.total ? `${model.done.toLocaleString()} of ${model.total.toLocaleString()} rows` : 'waiting for rows');
      tot.textContent = `${t.blocked} blocked · ${t.allowed} allowed · ${t.bypassed} bypassed · ${t.zpa} ZPA`;
    }
    function words() {
      alt.innerHTML = `<li>${E(model.total ? `${model.done} of ${model.total} row(s) tested${model.phase === 'lookup' ? ' (looking up categories first)' : ''}.` : 'No row tested yet.')}</li>`
        + model.boxes.map(b => `<li>${E(b.label)}: ${E(b.key === 'dest' || b.key === 'unverified' ? b.word : `${b.n} row(s)${b.n ? `: ${b.word}` : ''}`)}</li>`).join('');
    }
    let tween = null;
    function update(p) {
      if (!p) return;
      const prev = {};
      model.boxes.forEach(b => { prev[b.key] = b.n; });
      model = listFlowModel(p);
      words();
      const from = Object.assign({}, shown), to = {};
      model.boxes.forEach(b => { to[b.key] = b.n; });
      if (!want() || root.document.hidden) { Object.assign(shown, to); draw(); return; }
      model.boxes.forEach(b => {
        const gain = b.n - (prev[b.key] || 0);
        for (let k = 0; k < Math.min(gain, 5); k++) setTimeout(() => sendDot(b.key), k * 110);
      });
      if (tween) tween();
      let t0 = null;
      tween = clock.add(now => {
        frames++; host.setAttribute('data-lf-frames', String(frames));
        if (t0 === null) t0 = now;
        const k = Math.min(1, (now - t0) / 900);
        Object.keys(to).forEach(key => { shown[key] = from[key] + (to[key] - from[key]) * k; });
        draw();
        if (k >= 1 && tween) { tween(); tween = null; }
      });
    }
    function sendDot(key) {
      const e = P[key];
      if (!e || !e.getTotalLength || !want()) return;
      const L = e.getTotalLength(), dot = svgEl('circle', { r: 4, class: 'fa-dot small' + (key === 'dest' || key === 'zpa' ? '' : key === 'unverified' || key === 'client_connector' ? ' warn' : ' bad') }, dotsG);
      let t0 = null;
      const off = clock.add(now => {
        frames++; host.setAttribute('data-lf-frames', String(frames));
        if (t0 === null) t0 = now;
        const k = Math.min(1, (now - t0) / 700), q = e.getPointAtLength(L * k);
        dot.setAttribute('cx', q.x); dot.setAttribute('cy', q.y);
        if (k >= 1) { off(); dot.remove(); }
      });
    }
    function setBtn() { btn.textContent = want() ? 'Pause motion' : 'Play motion'; }
    btn.addEventListener('click', () => { chosen = !want(); if (!want()) { clock.clear(); tween = null; if (dotsG) dotsG.innerHTML = ''; model.boxes.forEach(b => { shown[b.key] = b.n; }); draw(); } setBtn(); });
    build(); words(); setBtn();
    return { update, frames: () => frames, model: () => model, destroy() { clock.destroy(); host.innerHTML = ''; } };
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

  // The route one trace takes, by the same tests the report's summary
  // uses: bypassed = !reaches_zscaler; left encrypted = !conditional,
  // reaches, outcome not blocked, SSL hop blind; enforce / monitor = the
  // outcome. Returns node keys, first to last.
  function dfRoute(t) {
    const hop = k => (t.hops || []).filter(h => h.key === k)[0] || {};
    const firstOf = (keys, st) => keys.filter(k => st.indexOf(hop(k).status) >= 0)[0];
    // The same one class per path as the summary (data_flow.visibility,
    // static/data_flow.js _dfVisibility): blocked, unverified, bypassed,
    // blind (still encrypted), then the DLP outcome.
    const r = ['src', 'cc'];
    const ssl = hop('ssl').status;
    if (t.outcome === 'blocked') {
      r.push('pac', 'policy');
      const blockedAt = firstOf(['cac', 'url', 'ssl', 'ftc'], ['blocked']);
      if (blockedAt === 'cac' || blockedAt === 'url') return r.concat(['b_policy']);
      r.push('ssl');
      if (blockedAt === 'ssl' || !t.decrypted) return r.concat(['b_ssl']);
      return r.concat(['dlp', 'o_block']);
    }
    if (t.conditional) {
      return firstOf(['zcc', 'forwarding'], ['unknown', 'warn']) || hop('pac').status !== 'unknown' ? r.concat(['u_cc']) : r.concat(['pac', 'u_pac']);
    }
    if (t.policy_conditional || ['unknown', 'out_of_scope', 'conditional'].indexOf(ssl) >= 0) return r.concat(['pac', 'policy', 'ssl', 'u_ssl']);
    if (!t.reaches_zscaler) {
      if (firstOf(['zcc', 'forwarding', 'pac'], ['bypass']) === 'pac') return r.concat(['pac', 'x_pac']);
      return r.concat(['x_cc']);
    }
    r.push('pac', 'policy', 'ssl');
    if (!t.decrypted) return r.concat(['enc']);
    r.push('dlp');
    r.push(t.outcome === 'enforce' ? 'o_enforce' : t.outcome === 'monitor' ? 'o_monitor' : 'o_other');
    if (hop('incident').status === 'conditional') r.push('incident');
    return r;
  }

  function dataFlowModel(report) {
    if (!report || !Array.isArray(report.traces) || !report.summary) return null;
    const s = report.summary, nets = {};
    (report.networks || []).forEach(n => { nets[n.key] = n.label || n.key; });
    const m = { kind: 'dataflow', cols: DF_COLS.slice(), nodes: [], links: [], routes: [], total: s.traces, unit: 'paths', summary: {}, counts: {}, mismatch: [] };
    // Every visibility class the summary counts (data_flow.visibility); a stored
    // report from before blocked / unverified / decrypted_other has only the first five.
    const CLASSES = ['traces', 'bypassed', 'blind', 'enforced', 'monitored', 'blocked', 'unverified', 'decrypted_other'];
    const checked = CLASSES.filter((k, i) => i < 5 || k in s);
    checked.forEach(k => { m.summary[k] = s[k]; });
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
      unverified: n('u_cc') + n('u_pac') + n('u_ssl'), decrypted_other: n('o_other'),
    };
    // Every path ends in exactly one place, and the named streams are
    // the summary's own numbers.
    const terminal = ['x_cc', 'x_pac', 'u_cc', 'u_pac', 'b_policy', 'b_ssl', 'u_ssl', 'enc', 'o_block', 'o_enforce', 'o_monitor', 'o_other'];
    m.terminals = terminal.filter(k => value[k]).map(k => ({ key: k, label: DF_NODES[k][1], tone: DF_NODES[k][2], count: n(k), share: pctOf(n(k), s.traces) }));
    checked.forEach(k => {
      if (m.counts[k] !== s[k]) m.mismatch.push(`${k}: picture ${m.counts[k]}, summary ${s[k]}`);
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
    // A Path analyzer result in the module shape (ZPA, PAC, ZIA modules, what-if).
    traffic: {
      source: 'device', network: 'off', platform: 'windows', zia_applies: true,
      destination: { input: 'files.example/upload', host: 'files.example', scheme: 'https', port: null },
      trace: { hops: [
        { key: 'zpa_segment', label: 'ZPA app segment', status: 'na', detail: 'No enabled ZPA application segment covers files.example:443/TCP, so ZPA does not carry it.' },
        { key: 'zcc', label: 'Client Connector app profile', status: 'pass', decided_by: { name: 'Default app profile' }, detail: 'No bypass for this host.' },
        { key: 'forwarding', label: 'Forwarding profile', status: 'pass', decided_by: { name: 'Remote workers' }, detail: 'Off network: Z-Tunnel 2.0.' },
        { key: 'pac', label: 'PAC file', status: 'pass', decided_by: { name: 'corp.pac' }, detail: 'PAC \'corp.pac\' sends files.example to Zscaler.' }] },
      modules: [
        { key: 'zpa_segment', module: 'ZPA application segment', verdict: 'not_matched', rule: null, overlaps: [], could_override: [], criteria: [], notes: ['No enabled ZPA application segment covers files.example:443/TCP, so ZPA does not carry it.'], detail: '' },
        { key: 'pac', module: 'PAC file', verdict: 'forwarded', rule: { name: 'corp.pac', order: null }, overlaps: [], could_override: [], criteria: [], notes: ['Evaluated, never run.'], detail: '' }],
      zia_modules: {
        traffic: { label: 'TCP/443 (HTTPS (web))', web: true }, stops_at: 'url', certainty: 'conditional', reasons: ['Cloud App Control: the deciding rule has a condition that cannot be evaluated.'],
        modifier: { key: 'ssl', module: 'SSL inspection', verdict: 'decrypt', certainty: 'definite', rule: { name: 'Decrypt all', order: 1 }, criteria: [], notes: [], detail: 'Decrypted: the later modules see the content.' },
        modules: [
          { key: 'atp', module: 'Advanced Threat Protection', verdict: 'allow', certainty: 'definite', rule: null, criteria: [], notes: [], detail: 'No threat category or denylist entry matches.' },
          { key: 'firewall', module: 'Cloud Firewall', verdict: 'allow', certainty: 'definite', rule: { name: 'Allow web', order: 3 }, criteria: [], notes: [], detail: '' },
          { key: 'dns', module: 'DNS Control', verdict: 'allow', certainty: 'definite', rule: { name: 'Allow lookups', order: 2 }, criteria: [], notes: [], detail: '' },
          { key: 'cac', module: 'Cloud App Control', verdict: 'block', certainty: 'conditional', rule: { name: 'Block uploads for interns', order: 1 }, criteria: [{ name: 'Group', state: 'unknown' }], notes: [], detail: 'Blocks uploads when the user is in the group Interns.' },
          { key: 'url', module: 'URL filtering', verdict: 'block', certainty: 'definite', rule: { name: 'Block file sharing', order: 4 }, criteria: [{ name: 'URL category', state: 'match' }], notes: [], detail: 'The category File Sharing is blocked.' },
          { key: 'sandbox', module: 'Sandbox', verdict: 'not_reached', certainty: 'definite', rule: null, criteria: [], notes: [], detail: 'Not reached: URL filtering ends the transaction first.' },
          { key: 'ftc', module: 'File Type Control', verdict: 'not_reached', certainty: 'definite', rule: null, criteria: [], notes: [], detail: 'Not reached.' },
          { key: 'dlp', module: 'Inline Web DLP', verdict: 'not_reached', certainty: 'definite', rule: null, criteria: [], notes: [], detail: 'Not reached.' }] },
      verdict: { outcome: 'blocked', certainty: 'conditional', headline: 'Blocked by URL filtering rule \'Block file sharing\'.', summary: 'Reference configuration; no transaction observed.' },
      whatif: { identity: { group: [{ name: 'Interns' }] }, identity_label: 'group Interns', depends_on: [] },
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
    trafficPathModel, listFlowModel, ARCH, SAMPLE, hopPlayer, drill, graph, live, steps, trafficPath, listFlow, E,
    dataFlowModel, dfRoute, sslWalkModel, sslCoverageModel, river, streams, ruleWalk, playButton, altList,
  };
  // The engine's parts, for the pages that draw their own pictures with it
  // (static/flow_pages.js): one clock, one way to draw boxes and links.
  Object.assign(FA, { animator, newSvg, box, curve, svgEl, fly, reduced, clip });
  root.FA = FA;
  if (typeof module !== 'undefined' && module.exports) module.exports = FA;
})(typeof window !== 'undefined' ? window : globalThis);
