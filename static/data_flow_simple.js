// ── Data flow map: the simple view for first-time readers ────────────
// One traced path as numbered steps in the order the traffic meets them
// (device → Client Connector → forwarding → PAC → Cloud App Control and
// URL Filtering → SSL inspection → File Type Control → Web DLP → the
// destination), one plain sentence per step, a decision word and a shape
// for each step (never colour alone, WCAG 1.4.1), a legend beside it, the
// details of one step at a time (hover, focus or click), and an optional
// walk-through (Back / Next). When the report carries traffic numbers
// (report.traffic, from ZIA Insights) a picture shows where the uploaded
// bytes really go on the chosen path's network, tied to that path by one
// sentence; it starts still (Play motion is opt-in); without numbers there
// is no picture and the page says why. Every fact the full map shows stays in "Show all
// details" (report_dataflow.html). Built with DOM calls and textContent
// only: rule and destination names are tenant data.
(function (root) {
  'use strict';
  const doc = root.document;

  // The decisions, each with a word, a meaning and a shape.
  const DEC = {
    start: { word: 'Start', meaning: 'Where the request begins.' },
    allowed: { word: 'Allowed', meaning: 'It goes on to the next step.' },
    inspected: { word: 'Inspected', meaning: 'Zscaler opens it and looks inside.' },
    notinspected: { word: 'Not inspected', meaning: 'It goes on locked. Zscaler cannot see inside.' },
    blocked: { word: 'Blocked', meaning: 'It is stopped here.' },
    bypassed: { word: 'Bypassed', meaning: 'It skips Zscaler, so nothing after this checks it.' },
    unsure: { word: 'Not sure', meaning: 'The settings that were read do not say.' },
    skipped: { word: 'Not reached', meaning: 'The request never gets here.' },
  };
  const DEC_ORDER = ['start', 'allowed', 'inspected', 'notinspected', 'blocked', 'bypassed', 'unsure', 'skipped'];
  // Shapes (SVG paths in a 20 x 20 box): circle with a tick, magnifier,
  // triangle with a bar, octagon with a cross, arrow leaving, diamond with a
  // question mark, dashed ring, filled dot.
  const SHAPE = {
    start: [['circle', { cx: 10, cy: 10, r: 6, class: 'fill' }]],
    allowed: [['circle', { cx: 10, cy: 10, r: 8 }], ['path', { d: 'M6 10.5 L9 13.5 L14.5 7' }]],
    inspected: [['circle', { cx: 8.5, cy: 8.5, r: 5.5 }], ['path', { d: 'M12.5 12.5 L17.5 17.5' }]],
    notinspected: [['path', { d: 'M10 2.5 L18 17 L2 17 Z' }], ['path', { d: 'M7 12.5 L13 12.5' }]],
    blocked: [['path', { d: 'M6.7 2 L13.3 2 L18 6.7 L18 13.3 L13.3 18 L6.7 18 L2 13.3 L2 6.7 Z' }], ['path', { d: 'M7 7 L13 13 M13 7 L7 13' }]],
    bypassed: [['path', { d: 'M3 15 C6 15 8 13 9 10 C10 7 12 5 16 5' }], ['path', { d: 'M12.5 2.5 L16.5 5 L12.5 7.5' }]],
    unsure: [['path', { d: 'M10 1.5 L18.5 10 L10 18.5 L1.5 10 Z' }], ['path', { d: 'M8 8 C8 5.5 12 5.5 12 8 C12 9.5 10 9.8 10 11.5 M10 13.6 L10 14.2' }]],
    skipped: [['circle', { cx: 10, cy: 10, r: 7.5, class: 'dash' }]],
  };
  const SVGNS = 'http://www.w3.org/2000/svg';
  function shape(dec) {
    const s = doc.createElementNS(SVGNS, 'svg');
    s.setAttribute('viewBox', '0 0 20 20'); s.setAttribute('width', '20'); s.setAttribute('height', '20');
    s.setAttribute('aria-hidden', 'true'); s.setAttribute('focusable', 'false');
    s.setAttribute('class', `dfs-shape dec-${dec}`);
    (SHAPE[dec] || SHAPE.unsure).forEach(([tag, attrs]) => {
      const e = doc.createElementNS(SVGNS, tag);
      Object.keys(attrs).forEach(k => e.setAttribute(k, attrs[k]));
      s.appendChild(e);
    });
    return s;
  }
  const el = (tag, cls, text) => { const e = doc.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };

  const winWords = tr => { const l = String((tr.window && tr.window.label) || 'the last 7 days'); return /^last /i.test(l) ? 'the ' + l.toLowerCase() : l; };

  // The words a newcomer may not know, from the Simple mode glossary.
  function termDef(key) { const G = root.SIMPLE_GLOSSARY || {}; return G[key] || null; }

  // A hop's status → one of the decisions.
  function decOf(h, key) {
    const s = h ? h.status : 'skipped';
    if (s === 'blocked' || s === 'zpa_denied') return 'blocked';
    if (s === 'bypass') return 'bypassed';
    if (s === 'skipped' || s === 'not_reached') return 'skipped';
    if (['unknown', 'conditional', 'out_of_scope', 'zpa_conditional', 'na', 'assumed'].indexOf(s) >= 0) return 'unsure';
    if (s === 'blind') return 'notinspected';
    if (key === 'ssl' && s === 'pass') return 'inspected';
    if (key === 'dlp' && (s === 'enforce' || s === 'monitor')) return 'inspected';
    return 'allowed';
  }
  const WORST = ['blocked', 'bypassed', 'notinspected', 'unsure', 'inspected', 'allowed', 'skipped'];
  function worst(decs) {
    const live = decs.filter(d => d !== 'skipped');
    if (!live.length) return 'skipped';
    return WORST.filter(d => live.indexOf(d) >= 0)[0] || 'allowed';
  }

  const CAP = {
    zcc: { allowed: 'Client Connector, the Zscaler app on the device, sends it to Zscaler.', bypassed: 'Client Connector lets it skip Zscaler. This is a bypass.',
      unsure: 'The settings do not say what Client Connector does with it.', skipped: 'Client Connector does not handle it.' },
    pac: { allowed: 'The PAC file sends it to Zscaler.', bypassed: 'The PAC file sends it straight to the internet.',
      unsure: 'The settings do not say what the PAC file answers.', skipped: 'The PAC file is not used.' },
    policy: { allowed: 'Cloud App Control and URL Filtering let it go on.', blocked: 'Cloud App Control or URL Filtering blocks it here.',
      unsure: 'Whether these rules let it go on depends on the user, or was not read.', notinspected: 'These rules see only the site name while it is locked.',
      skipped: 'It never gets here.' },
    ssl: { inspected: 'SSL inspection unlocks it, so Zscaler can look inside.', notinspected: 'SSL inspection leaves it locked, so Zscaler cannot look inside.',
      blocked: 'SSL inspection blocks it here.', unsure: 'The settings do not say if SSL inspection unlocks it.', allowed: 'SSL inspection lets it go on.',
      skipped: 'It never gets here.' },
    ftc: { allowed: 'File Type Control lets this kind of file go on.', blocked: 'File Type Control blocks this kind of file.',
      notinspected: 'File Type Control cannot see the file while it is locked.', unsure: 'The settings do not say what File Type Control does.',
      skipped: 'It never gets here.' },
    dlp: { allowed: 'No Web DLP rule looks at it.', notinspected: 'Web DLP cannot look, because the data is still locked.',
      unsure: 'The settings do not say if a Web DLP rule looks at it.', blocked: 'Web DLP blocks it.', skipped: 'It never gets here.' },
  };

  // The numbered steps of one traced path.
  function stepsOf(t, report) {
    const hop = k => (t.hops || []).filter(h => h.key === k)[0];
    const nets = {}; ((report && report.networks) || []).forEach(n => { nets[n.key] = n.label || n.key; });
    const net = nets[t.network] || t.network || 'this network';
    const dest = (t.destination && t.destination.label) || 'the website';
    const out = [];
    out.push({ key: 'device', title: 'Your device', dec: 'start', hops: [], terms: [],
      cap: `A ${t.platform || 'managed'} device sends a request to ${dest}.` });
    const zcc = hop('zcc');
    if (zcc) { const d = decOf(zcc, 'zcc'); out.push({ key: 'zcc', title: 'Client Connector', dec: d, hops: [zcc], terms: ['client connector', 'bypass'], cap: CAP.zcc[d] || CAP.zcc.allowed }); }
    const fwd = hop('forwarding');
    if (fwd) {
      const d = decOf(fwd, 'forwarding');
      const cap = { allowed: `On ${net}, the forwarding setting sends it to Zscaler.`, bypassed: `On ${net}, the forwarding setting sends it straight to the internet.`,
        unsure: `On ${net}, the settings do not say where it is sent.`, skipped: 'The forwarding setting is not used.' }[d] || `On ${net}, the forwarding setting sends it on.`;
      out.push({ key: 'forwarding', title: 'Forwarding', dec: d, hops: [fwd], terms: ['forwarding profile', 'cloud'], cap });
    }
    const pac = hop('pac');
    if (pac && ['skipped', 'not_reached', 'na'].indexOf(pac.status) < 0) { const d = decOf(pac, 'pac'); out.push({ key: 'pac', title: 'PAC file', dec: d, hops: [pac], terms: ['pac file'], cap: CAP.pac[d] || CAP.pac.allowed }); }
    const pol = [hop('cac'), hop('url')].filter(Boolean);
    if (pol.length) {
      const d = worst(pol.map(h => decOf(h, h.key)));
      out.push({ key: 'policy', title: 'Cloud App Control and URL Filtering', dec: d, hops: pol, terms: ['cloud app control', 'url filtering'], cap: CAP.policy[d] || CAP.policy.allowed });
    }
    ['ssl', 'ftc', 'dlp'].forEach(k => {
      const h = hop(k);
      if (!h) return;
      const d = decOf(h, k);
      let cap = CAP[k][d] || CAP[k].allowed;
      if (k === 'dlp' && d === 'inspected') cap = h.status === 'monitor' ? 'Web DLP looks for private data, but only writes down what it finds.' : 'Web DLP looks for private data and can block it.';
      const extra = k === 'dlp' ? [hop('incident')].filter(Boolean) : [];
      out.push({ key: k, title: { ssl: 'SSL inspection', ftc: 'File Type Control', dlp: 'Web DLP' }[k], dec: d, hops: [h].concat(extra),
        terms: { ssl: ['ssl inspection', 'encrypted'], ftc: ['file type control'], dlp: ['dlp', 'incident receiver'] }[k], cap });
    });
    // The destination: where the request ends up, from the path's outcome.
    const o = t.outcome;
    const end = o === 'bypassed' ? ['bypassed', `It reaches ${dest} with no Zscaler check.`]
      : o === 'blocked' || o === 'zpa_denied' ? ['blocked', `It never reaches ${dest}.`]
        : o === 'blind' ? ['notinspected', `It reaches ${dest}, but nobody looked inside.`]
          : o === 'enforce' ? ['inspected', `It reaches ${dest} after Web DLP checked it.`]
            : o === 'monitor' ? ['inspected', `It reaches ${dest}. Web DLP checked it, but only watches.`]
              : o === 'none' || o === 'metadata_only' || o === 'zpa_allowed' ? ['allowed', `It reaches ${dest}. No DLP rule checked what is inside.`]
                : ['unsure', `The settings do not say for sure what reaches ${dest}.`];
    out.push({ key: 'dest', title: dest, dec: end[0], hops: [], terms: [], cap: end[1], weak: t.weak_points || [] });
    return out;
  }

  // ── Render ────────────────────────────────────────────────────────
  // opts.onDetails(stepKey): open "Show all details" at that step.
  function render(report, container, opts) {
    const o = opts || {};
    container.textContent = '';
    const FA = root.FA;
    const nets = {}; (report.networks || []).forEach(n => { nets[n.key] = n.label || n.key; });
    const wrap = el('section', 'dfs'); wrap.id = 'dfSimple'; wrap.setAttribute('aria-labelledby', 'dfsHowH');

    const how = el('div', 'dfs-howto');
    const hh = el('h2', 'dfs-h', 'How to read this map'); hh.id = 'dfsHowH';
    how.appendChild(hh);
    how.appendChild(el('p', 'dfs-lead', 'Read the steps from top to bottom. Each step is one check that web traffic meets on its way from a computer to a website. The shape and the word next to each step say what that check does, and the legend says what each one means.'));
    wrap.appendChild(how);

    const top = el('div', 'dfs-top');
    const lab = el('label', 'df-ctl');
    lab.appendChild(el('span', 'lbl', 'Path to show'));
    const sel = el('select'); sel.id = 'dfsPath';
    report.traces.forEach((t, i) => {
      const op = el('option', '', `${(t.destination || {}).label || 'Destination'} · ${nets[t.network] || t.network}`);
      op.value = String(i); sel.appendChild(op);
    });
    lab.appendChild(sel); top.appendChild(lab);
    const walk = el('button', 'rp-btn', 'Walk me through it'); walk.type = 'button'; walk.id = 'dfsWalk';
    top.appendChild(walk);
    wrap.appendChild(top);

    const grid = el('div', 'dfs-grid');
    const main = el('div', 'dfs-main');
    const result = el('p', 'dfs-result'); result.id = 'dfsResult'; result.setAttribute('aria-live', 'polite');
    main.appendChild(result);
    const ol = el('ol', 'dfs-steps'); ol.id = 'dfsSteps'; ol.setAttribute('aria-label', 'Steps, in the order the traffic meets them');
    main.appendChild(ol);
    const bar = el('div', 'dfs-walkbar'); bar.id = 'dfsWalkBar'; bar.hidden = true;
    const back = el('button', 'rp-btn', 'Back'); back.type = 'button'; back.id = 'dfsBack';
    const pos = el('span', 'dfs-pos'); pos.id = 'dfsWalkPos';
    const next = el('button', 'rp-btn primary', 'Next'); next.type = 'button'; next.id = 'dfsNext';
    const stop = el('button', 'rp-btn', 'End the walk-through'); stop.type = 'button'; stop.id = 'dfsWalkEnd';
    [back, pos, next, stop].forEach(x => bar.appendChild(x));
    main.appendChild(bar);
    const detail = el('div', 'dfs-detail'); detail.id = 'dfsDetail'; detail.setAttribute('role', 'region'); detail.setAttribute('aria-live', 'polite');
    detail.setAttribute('aria-label', 'Details of the chosen step');
    main.appendChild(detail);
    grid.appendChild(main);

    const legend = el('aside', 'dfs-legend'); legend.id = 'dfsLegend'; legend.setAttribute('aria-labelledby', 'dfsLegendH');
    const lh = el('h3', 'dfs-h3', 'Legend'); lh.id = 'dfsLegendH'; legend.appendChild(lh);
    const lul = el('ul', 'dfs-legend-list');
    DEC_ORDER.forEach(k => {
      const li = el('li', `dfs-leg dec-${k}`); li.dataset.dec = k;
      li.appendChild(shape(k));
      const tx = el('span', 'dfs-leg-t');
      tx.appendChild(el('strong', '', DEC[k].word));
      tx.appendChild(doc.createTextNode(' ' + DEC[k].meaning));
      li.appendChild(tx); lul.appendChild(li);
    });
    legend.appendChild(lul);
    legend.appendChild(el('p', 'dfs-note', 'Each step shows its number, a shape and a word, so colour is never the only clue.'));
    grid.appendChild(legend);
    wrap.appendChild(grid);

    // Where uploads really go: only with traffic numbers.
    const tsec = el('section', 'dfs-traffic'); tsec.id = 'dfsTraffic'; tsec.setAttribute('aria-labelledby', 'dfsTrafficH');
    const th = el('h2', 'dfs-h', 'Where your uploads really go'); th.id = 'dfsTrafficH';
    tsec.appendChild(th);
    wrap.appendChild(tsec);
    container.appendChild(wrap);

    let steps = [], cur = -1, pinned = -1, walking = false, trace = null, pic = null, onTrace = null;

    function showDetail(i) {
      detail.textContent = '';
      const s = steps[i];
      if (!s) return;
      cur = i;
      ol.querySelectorAll('.dfs-step').forEach((li, j) => li.classList.toggle('on', j === i));
      const h = el('h3', 'dfs-h3', `Step ${i + 1}: ${s.title}`); h.id = 'dfsDetailH';
      detail.appendChild(h);
      const dl = el('p', `dfs-dline dec-${s.dec}`);
      dl.appendChild(shape(s.dec));
      dl.appendChild(el('strong', '', DEC[s.dec].word));
      dl.appendChild(doc.createTextNode(' — ' + DEC[s.dec].meaning));
      detail.appendChild(dl);
      detail.appendChild(el('p', 'dfs-cap', s.cap));
      s.hops.forEach(hp => {
        const box = el('div', 'dfs-hop');
        box.appendChild(el('strong', '', hp.label || hp.key));
        if (hp.decided_by && hp.decided_by.name) {
          const p = el('p', '', 'Decided by ');
          p.appendChild(el('code', '', hp.decided_by.name));
          if (hp.decided_by.order != null) p.appendChild(doc.createTextNode(` (rule order ${hp.decided_by.order})`));
          if (hp.decided_by.action) p.appendChild(doc.createTextNode(` · ${hp.decided_by.action}`));
          box.appendChild(p);
        }
        if (hp.why) box.appendChild(el('p', '', `Why: ${hp.why}.`));
        if (hp.detail) box.appendChild(el('p', 'dfs-dim', hp.detail));
        if (hp.weak_point) {
          const w = el('p', `dfs-weak sev-${hp.weak_point.severity}`);
          w.appendChild(el('strong', '', `Weak point (${hp.weak_point.severity}): ${hp.weak_point.title}.`));
          w.appendChild(doc.createTextNode(' ' + (hp.weak_point.fix || '')));
          box.appendChild(w);
        }
        detail.appendChild(box);
      });
      if (s.key === 'dest' && s.weak.length) {
        detail.appendChild(el('p', 'dfs-dim', `This path has ${s.weak.length} weak point${s.weak.length === 1 ? '' : 's'}; the steps that cause them say how to fix them.`));
      }
      const terms = s.terms.map(k => [k, termDef(k)]).filter(x => x[1]);
      if (terms.length) {
        detail.appendChild(el('h4', 'dfs-h4', 'Words to know'));
        const dlist = el('dl', 'dfs-terms');
        terms.forEach(([k, g]) => {
          const dt = el('dt'), a = el('a', 'dfs-term', g.term);
          a.href = '/help#glossary'; a.target = '_blank'; a.rel = 'noopener'; a.dataset.term = k;
          dt.appendChild(a); dlist.appendChild(dt);
          dlist.appendChild(el('dd', '', g.def));
        });
        detail.appendChild(dlist);
      }
      if (o.onDetails && s.key !== 'device') {
        const more = el('button', 'rp-btn dfs-more', 'Show this step in all details'); more.type = 'button'; more.id = 'dfsMore';
        more.addEventListener('click', () => o.onDetails(s.key));
        detail.appendChild(more);
      }
      if (walking) {
        pos.textContent = `Step ${i + 1} of ${steps.length}`;
        back.disabled = i === 0; next.disabled = i === steps.length - 1;
      }
    }

    function drawSteps() {
      ol.textContent = '';
      steps.forEach((s, i) => {
        const li = el('li', `dfs-step dec-${s.dec}`); li.dataset.step = s.key;
        const b = el('button', 'dfs-btn'); b.type = 'button'; b.dataset.i = String(i);
        b.setAttribute('aria-controls', 'dfsDetail');
        b.setAttribute('aria-pressed', i === pinned ? 'true' : 'false');
        b.appendChild(el('span', 'dfs-num', String(i + 1)));
        b.appendChild(shape(s.dec));
        const tx = el('span', 'dfs-text');
        tx.appendChild(el('span', 'dfs-title', s.title));
        tx.appendChild(el('span', 'dfs-cap', s.cap));
        b.appendChild(tx);
        b.appendChild(el('span', 'dfs-dec', DEC[s.dec].word));
        const preview = () => { if (!walking) showDetail(i); };
        const restore = () => { if (!walking && pinned >= 0 && pinned !== i) showDetail(pinned); };
        b.addEventListener('mouseenter', preview);
        b.addEventListener('focus', preview);
        b.addEventListener('mouseleave', restore);
        b.addEventListener('click', () => { pin(i); });
        li.appendChild(b);
        ol.appendChild(li);
      });
    }
    function pin(i) {
      pinned = i;
      ol.querySelectorAll('.dfs-btn').forEach((b, j) => b.setAttribute('aria-pressed', j === i ? 'true' : 'false'));
      showDetail(i);
    }
    // The step that matters most: the first one that stops, skips or
    // leaves the traffic locked; else the last (where it ends).
    function keyStep() {
      const k = steps.findIndex(s => ['blocked', 'bypassed', 'notinspected', 'unsure'].indexOf(s.dec) >= 0);
      return k >= 0 ? k : steps.length - 1;
    }

    function show(t, index) {
      trace = t;
      steps = stepsOf(t, report);
      if (index != null && index >= 0) sel.value = String(index);
      else {
        let op = sel.querySelector('option[value="custom"]');
        if (!op) { op = el('option'); op.value = 'custom'; sel.appendChild(op); }
        op.textContent = `${(t.destination || {}).label || 'Destination'} · ${nets[t.network] || t.network} (typed)`;
        sel.value = 'custom';
      }
      result.textContent = '';
      result.appendChild(el('strong', '', 'In short: '));
      result.appendChild(doc.createTextNode(steps[steps.length - 1].cap));
      endWalk(false);
      drawSteps();
      pin(keyStep());
      if (onTrace) onTrace(t);
    }

    function startWalk() {
      walking = true; bar.hidden = false; walk.setAttribute('aria-expanded', 'true');
      showDetail(0); next.focus();
    }
    function endWalk(focus) {
      if (!walking) return;
      walking = false; bar.hidden = true; walk.setAttribute('aria-expanded', 'false');
      showDetail(pinned >= 0 ? pinned : 0);
      if (focus) walk.focus();
    }
    walk.setAttribute('aria-expanded', 'false'); walk.setAttribute('aria-controls', 'dfsWalkBar');
    walk.addEventListener('click', () => (walking ? endWalk(true) : startWalk()));
    back.addEventListener('click', () => { if (cur > 0) showDetail(cur - 1); if (back.disabled) next.focus(); });
    next.addEventListener('click', () => { if (cur < steps.length - 1) showDetail(cur + 1); if (next.disabled) back.focus(); });
    stop.addEventListener('click', () => endWalk(true));
    bar.addEventListener('keydown', e => { if (e.key === 'Escape') { e.preventDefault(); endWalk(true); } });
    sel.addEventListener('change', () => {
      const i = Number(sel.value);
      if (sel.value !== 'custom' && report.traces[i]) { show(report.traces[i], i); if (o.onPath) o.onPath(i); }
    });

    // The traffic picture.
    const tr = report.traffic || {};
    const model0 = FA && FA.dataFlowTrafficModel ? FA.dataFlowTrafficModel(report) : null;
    if (!model0) {
      const p = el('p', 'dfs-note');
      p.id = 'dfsNoTraffic';
      p.textContent = (tr.reason || 'Traffic numbers were not read, so this map shows settings only.')
        + ' The numbered steps above show what the settings decide. With ZIA Insights in scope, this space shows how much of your real uploads takes each road.';
      tsec.appendChild(p);
    } else {
      // One plain sentence ties the picture to the path above.
      const said = el('p', 'dfs-trafpath'); said.id = 'dfsTrafficPath';
      tsec.appendChild(said);
      const lead = el('p', 'dfs-lead');
      tsec.appendChild(lead);
      const row = el('div', 'dfs-top');
      const nl = el('label', 'df-ctl'); nl.appendChild(el('span', 'lbl', 'Network'));
      const ns = el('select'); ns.id = 'dfsNet';
      (report.networks || []).forEach(n => { const op = el('option', '', n.label || n.key); op.value = n.key; ns.appendChild(op); });
      nl.appendChild(ns); row.appendChild(nl);
      const play = el('button', 'rp-btn'); play.type = 'button'; play.id = 'dfsFlowPlay';
      row.appendChild(play);
      tsec.appendChild(row);
      const stage = el('div', 'fa-stage dfs-stage'); stage.id = 'dfsFlowStage';
      tsec.appendChild(stage);
      const pick = el('p', 'fa-pick'); pick.id = 'dfsFlowPick'; pick.setAttribute('role', 'status'); pick.setAttribute('aria-live', 'polite');
      pick.textContent = 'Point at or focus a stream for its share. Press Enter on it to show that path in the steps above.';
      tsec.appendChild(pick);
      tsec.appendChild(el('h3', 'dfs-h3', 'The same, in words'));
      const altHost = el('div'); tsec.appendChild(altHost);
      tsec.appendChild(el('p', 'dfs-note', tr.basis || ''));
      const draw = network => {
        if (pic) pic.destroy();
        const m = FA.dataFlowTrafficModel(report, network);
        lead.textContent = `This picture uses real numbers: the data your users uploaded to cloud apps in ${winWords(tr)}. Each stream is as wide as its share. `
          + (m && m.unchecked ? 'A red stream ends where the data is not checked.' : 'None of the counted uploads took a road where the data is not checked.')
          + ' The picture starts still, because the widths say it all; Play motion shows the data moving.';
        altHost.textContent = '';
        if (!m) { stage.textContent = ''; pic = null; altHost.appendChild(el('p', 'dfs-note', 'No uploads were counted for this network.')); syncPlay(); return; }
        FA.altList(altHost, m.alt, 'dfsFlowAlt');
        pic = FA.river(stage, m, {
          height: 200, autoplay: false,   // motion adds nothing the widths do not say: Play is opt-in
          onFocus: l => { pick.textContent = l ? l.label : 'Point at or focus a stream for its share. Press Enter on it to show that path in the steps above.'; },
          onPick: l => { const it = l.items && l.items[0]; if (it && report.traces[it.i]) { show(report.traces[it.i], it.i); const b = ol.querySelector('.dfs-btn[aria-pressed="true"]'); if (b) b.focus(); } },
        });
        pic.svg.setAttribute('aria-describedby', 'dfsFlowAlt');
        syncPlay();
      };
      const syncPlay = FA.playButton(play, () => [pic]);
      ns.addEventListener('change', () => draw(ns.value));
      // The path above: its share of the uploads and what happens to that
      // data; the picture shows that path's network.
      onTrace = t => {
        said.textContent = '';
        const ps = FA.dataFlowPathShare ? FA.dataFlowPathShare(report, t) : null;
        if (t && t.network && t.network !== ns.value && [...ns.options].some(op => op.value === t.network)) { ns.value = t.network; draw(ns.value); }
        if (!ps) {
          const k = t && t.destination && t.destination.kind === 'class' && t.destination.class;
          said.textContent = k && tr.classes[k] ? 'No uploads were counted on the network of the path above, so this picture has nothing to show for it.'
            : 'The path above is not one of the traffic classes ZIA Insights counts, so this picture cannot say how much of your uploads took it.';
          return;
        }
        const where = `${ps.label}, on ${nets[t.network] || t.network}`;
        const pct = ps.share > 0 && ps.share < 0.005 ? 'under 1%' : `${Math.round(100 * ps.share)}%`;
        said.appendChild(doc.createTextNode(`The path above, ${where}, carried `));
        said.appendChild(el('strong', '', pct));
        if (ps.bytes > 0) {
          said.appendChild(doc.createTextNode(` (${FA.humanBytes(ps.bytes)}) of the ${FA.humanBytes(ps.total)} your users uploaded in ${ps.window}. On this network, that data `));
          said.appendChild(el('strong', '', ps.now));
          said.appendChild(doc.createTextNode('.'));
        } else {
          said.appendChild(doc.createTextNode(` of the ${FA.humanBytes(ps.total)} your users uploaded in ${ps.window}: no uploads were seen there. If people start uploading to ${ps.label}, that data `));
          said.appendChild(el('strong', '', ps.would));
          said.appendChild(doc.createTextNode('.'));
        }
      };
      draw(ns.value);
      if (trace) onTrace(trace);
    }

    return {
      show, steps: () => steps.slice(), current: () => cur,
      picture: () => pic,
      destroy() { if (pic) pic.destroy(); container.textContent = ''; },
    };
  }

  root.DataFlowSimple = { render, stepsOf, decOf, DEC, DEC_ORDER };
})(typeof window !== 'undefined' ? window : globalThis);
