// ── Traffic and session logs (static/report_traffic_logs.html) ─────────
// Uploads ZPA LSS and ZIA NSS log files to this computer's server
// (/api/traffic-logs/analyze), draws what comes back, links destinations
// to the Path analyzer and the time window to Traffic insights, exports
// with the server's exporters and shows the SIEM query templates.
//
// Every value in a report comes from an uploaded log, so it is untrusted:
// this script never builds HTML from it. Every node is made with
// createElement and filled with textContent (el() below); a link's target
// is built from a fixed path and encodeURIComponent, never from log text.
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const SVG = 'http://www.w3.org/2000/svg';
  let chosen = [];
  let report = null;
  let limitBytes = 7 * 1024 * 1024;
  let siemTimer = null;
  // The session list's Client Connector version and platform filter; the downloads use it too.
  const sessFilter = { version: '', platform: '' };

  // el('tag', {attr: value, class: 'x', text: 'y', on: {click: fn}}, child, ...)
  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'text') n.textContent = String(v);
      else if (k === 'class') n.className = v;
      else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
      else n.setAttribute(k, v === true ? '' : String(v));
    }
    for (const c of kids.flat()) if (c != null && c !== false) n.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
    return n;
  }
  function svg(tag, attrs, ...kids) {
    const n = document.createElementNS(SVG, tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v != null) n.setAttribute(k, String(v));
    for (const c of kids) if (c) n.appendChild(c);
    return n;
  }
  const fmt = n => (typeof n === 'number' && Number.isFinite(n)) ? n.toLocaleString() : String(n == null ? '' : n);
  const pct = (a, b) => b ? `${Math.round((a / b) * 1000) / 10}%` : '0%';
  function announce(t) { const r = $('liveRegion'); if (r) { r.textContent = ''; setTimeout(() => { r.textContent = t; }, 30); } }
  function status(t, bad) { const s = $('tlStatus'); s.textContent = t; s.classList.toggle('bad', !!bad); }
  function setEnabled(id, on) { const b = $(id); if (!b) return; b.disabled = !on; b.setAttribute('aria-disabled', on ? 'false' : 'true'); }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }

  // ── Limits and the SIEM catalogue ──
  let info = null;
  fetch('/api/traffic-logs/info').then(r => r.json()).then(c => {
    info = c;
    limitBytes = Math.floor((c.max_body_mb || 10) * 1024 * 1024 * 0.72);
    $('tlLimit').textContent = `Up to about ${Math.floor(limitBytes / 1024 / 1024)} MB per upload (a .gz or .zip counts as its packed size, so pack big logs). Up to ${fmt(c.max_lines)} lines are read.`;
    $('tlLineKb').textContent = String(c.max_line_kb);
    $('tlMaxLines').textContent = fmt(c.max_lines);
    const q = $('tlQuestion');
    const groups = {};
    for (const x of (c.siem && c.siem.questions) || []) {
      const fam = (c.siem.families || {})[x.family] || x.family;
      if (!groups[fam]) { groups[fam] = el('optgroup', { label: fam }); q.appendChild(groups[fam]); }
      groups[fam].appendChild(el('option', { value: x.id, text: x.title }));
    }
    if (c.siem && c.siem.note) $('tlSiemNote').textContent = 'Copy a query to ask your SIEM the same question over all your logs. ' + c.siem.note;
    syncSourcePlaceholders();
    renderQuery();
  }).catch(() => { $('tlLimit').textContent = 'Could not read the upload limit from the server; try files under 7 MB.'; });
  loadSaved();

  // ── Choosing files ──
  function take(list) {
    const files = Array.from(list || []);
    if (!files.length) return;
    const total = files.reduce((a, f) => a + f.size, 0);
    chosen = files;
    $('tlChosen').textContent = `${files.length} file${files.length === 1 ? '' : 's'}, ${(total / 1024 / 1024).toFixed(2)} MB`;
    if (total > limitBytes) {
      status(`These files add up to ${(total / 1024 / 1024).toFixed(1)} MB, more than this server accepts in one go. Gzip them (logs shrink about ten times), upload fewer at a time, or start the server with a larger ZSCALER_MAX_BODY_MB.`, true);
      setEnabled('tlRun', false);
      return;
    }
    status('Ready. Click Analyze.');
    setEnabled('tlRun', true);
  }
  $('tlFiles').addEventListener('change', e => take(e.target.files));
  const drop = $('tlDrop');
  ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('is-over'); }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('is-over'); }));
  drop.addEventListener('drop', e => take(e.dataTransfer && e.dataTransfer.files));

  function readFile(f) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onerror = () => reject(new Error(`Could not read ${f.name}`));
      r.onload = () => resolve({ name: f.name, content: String(r.result).split(',')[1] || '', encoding: 'base64' });
      r.readAsDataURL(f);
    });
  }

  $('tlRun').addEventListener('click', async () => {
    if (!chosen.length) return;
    setEnabled('tlRun', false);
    status('Reading the files…');
    let files;
    try { files = await Promise.all(chosen.map(readFile)); } catch (e) { status(e.message, true); setEnabled('tlRun', true); return; }
    await analyse(files, $('tlFormat').value || '', '');
  });

  // Try it without logs of your own: a small made-up ZIA NSS web log for the
  // sample tenant (static/samples), analysed like an upload.
  $('tlSample').addEventListener('click', async () => {
    setEnabled('tlRun', false); setEnabled('tlSample', false);
    status('Reading the sample web logs…');
    try {
      const r = await fetch('/static/samples/nss-web-sample.jsonl', { cache: 'no-store' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const text = await r.text();
      await analyse([{ name: 'sample-nss-web.jsonl', content: text }], '', 'Sample web logs (made up, for the sample tenant). ');
    } catch (e) { status(`Could not read the sample web logs: ${e.message}`, true); }
    finally { setEnabled('tlSample', true); setEnabled('tlRun', chosen.length > 0); }
  });

  async function analyse(files, feedFormat, what) {
    status('Analysing… a large log takes a few seconds.');
    announce('Analysing the logs');
    try {
      const r = await fetch('/api/traffic-logs/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files, feed_format: feedFormat }) });
      const data = await r.json().catch(() => ({}));
      if (r.status === 413) throw new Error('The upload is larger than this server accepts. Gzip the logs or upload fewer at a time.');
      if (!r.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `HTTP ${r.status}`);
      show(data);
      const inp = data.input || {};
      status(`${what}Done: ${fmt(inp.records)} records read${inp.malformed ? `, ${fmt(inp.malformed)} lines could not be read and were skipped` : ''}.`);
      announce('Analysis complete.');
    } catch (e) {
      status(`Could not analyse: ${e.message}`, true);
      announce('The analysis failed. ' + e.message);
    } finally { setEnabled('tlRun', chosen.length > 0); }
  }

  // ── Drawing ──
  function show(data) {
    report = data;
    $('tlResults').hidden = false;
    ['tlCsv', 'tlXlsx', 'tlPdf', 'tlSave', 'tlForget'].forEach(id => setEnabled(id, true));
    drawSummary(data);
    drawAnomalies(data);
    drawZpa(data);
    drawHealth(data);
    drawZia(data);
    drawNav();
    $('tlResultsH').focus();
  }

  function tile(k, v, s) { return el('div', { class: 'tl-tile' }, el('div', { class: 'k', text: k }), el('div', { class: 'v', text: v }), s ? el('div', { class: 's', text: s }) : null); }

  function drawSummary(d) {
    const inp = d.input || {};
    const p = d.period || {};
    const box = clear($('tlSummary'));
    box.appendChild(tile('Records read', fmt(inp.records), `${fmt(inp.lines)} lines`));
    box.appendChild(tile('Lines skipped', fmt((inp.malformed || 0) + (inp.oversized || 0)), `${fmt(inp.malformed)} unreadable, ${fmt(inp.oversized)} too long, ${fmt(inp.unrecognised)} JSON of another kind`));
    box.appendChild(tile('From', p.first || 'no times', 'as written in the logs'));
    box.appendChild(tile('To', p.last || 'no times', p.untimed_records ? `${fmt(p.untimed_records)} records had no time` : ''));
    for (const t of d.log_types || []) box.appendChild(tile(t.label, fmt(t.records), 'records'));
    if (d.counts_only) box.appendChild(tile('Saved as', 'Counts only', 'no user names or addresses'));
    const notes = clear($('tlNotes'));
    const lines = (inp.notes || []).slice();
    if (inp.capped) lines.push('Reading stopped at the line limit; the rest of the files was not read.');
    if (lines.length) notes.appendChild(el('p', { class: 'tl-dim', text: 'Note: ' + lines.join('; ') + '.' }));
    if ((inp.malformed_examples || []).length) {
      const det = el('details', {}, el('summary', { text: `Lines that could not be read (first ${inp.malformed_examples.length})` }));
      det.appendChild(table(['File', 'Line', 'Why'], inp.malformed_examples.map(x => [x.file, x.line, x.why]), [1]));
      notes.appendChild(det);
    }
  }

  // A table from rows of cells. A cell is text, a number or a node.
  function table(cols, rows, numCols) {
    const nums = new Set(numCols || []);
    const t = el('table', { class: 'tl-t' }, el('thead', {}, el('tr', {}, cols.map((c, i) => el('th', { scope: 'col', class: nums.has(i) ? 'num' : null, text: c })))));
    const tb = el('tbody');
    for (const r of rows) tb.appendChild(el('tr', {}, r.map((c, i) => el('td', { class: nums.has(i) ? 'num' : null }, c instanceof Node ? c : fmt(c)))));
    t.appendChild(tb);
    return el('div', { class: 'tl-wrap' }, t);
  }
  function box(title, id, ...kids) { return el('div', { class: 'tl-box', id }, el('h3', { text: title }), ...kids); }
  function more(rows, n) { return rows.slice(0, n); }

  // The destination cell: the name, a link to the Path analyzer (filled in,
  // never started) and a button that puts it in the SIEM query.
  function destCell(x) {
    const frag = el('span', {}, x.name);
    if (x.link) {
      const q = new URLSearchParams({ d: x.name });
      if (x.port && /^\d{1,5}$/.test(String(x.port))) q.set('port', String(x.port));
      if (x.proto === 'tcp' || x.proto === 'udp') q.set('proto', x.proto);
      frag.appendChild(el('a', { class: 'tl-link tl-act', href: '/report/path?' + q.toString(), target: '_blank', rel: 'noopener',
        'aria-label': `Analyze the path to ${x.name} (opens the Path analyzer in a new tab)`, text: 'Analyze path' }));
    }
    frag.appendChild(el('button', { type: 'button', class: 'tl-act', 'aria-label': `Use ${x.name} in the SIEM query`, text: 'SIEM query',
      on: { click: () => { $('tlQDest').value = x.name; renderQuery(); $('tlSiemSec').scrollIntoView({ block: 'start' }); $('tlQuery').focus(); } } }));
    return frag;
  }
  function userCell(name) {
    if (!name || report && report.counts_only) return el('span', {}, name || '');
    return el('span', {}, name, el('button', { type: 'button', class: 'tl-act', 'aria-label': `Use ${name} in the SIEM query`, text: 'SIEM query',
      on: { click: () => { $('tlQUser').value = name; renderQuery(); $('tlSiemSec').scrollIntoView({ block: 'start' }); $('tlQuery').focus(); } } }));
  }

  // Bars over time: series a (total) and b (failures or blocks) side by side
  // in each slot, with a native tooltip per slot and a table view.
  function chart(tl, a, b, labelA, labelB, title) {
    const pts = (tl && tl.points) || [];
    const ia = tl.series.indexOf(a), ib = tl.series.indexOf(b);
    const wrap = el('div', { class: 'tl-chart' });
    if (!pts.length || ia < 0) { wrap.appendChild(el('p', { class: 'tl-dim', text: 'No times in these records, so nothing to draw over time.' })); return wrap; }
    const W = 640, H = 160, P = 22;
    const max = Math.max(1, ...pts.map(p => Math.max(p.v[ia] || 0, ib >= 0 ? p.v[ib] || 0 : 0)));
    const slot = (W - P) / pts.length;
    const bw = Math.max(1, Math.min(14, (slot - 2) / (ib >= 0 ? 2 : 1)));
    const s = svg('svg', { viewBox: `0 0 ${W} ${H + 18}`, role: 'img', 'aria-label': `${title}: ${labelA}${ib >= 0 ? ' and ' + labelB : ''} per ${slotWords(tl.bucket_seconds)}, highest ${max}. The table below has every value.` });
    s.appendChild(svg('line', { x1: P, y1: H, x2: W, y2: H, class: 'axis' }));
    const t1 = svg('text', { x: 0, y: 10 }); t1.textContent = fmt(max); s.appendChild(t1);
    pts.forEach((p, i) => {
      const x = P + i * slot + 1;
      const g = svg('g', {});
      const tip = svg('title'); tip.textContent = `${p.t}: ${labelA} ${p.v[ia] || 0}${ib >= 0 ? `, ${labelB} ${p.v[ib] || 0}` : ''}`;
      g.appendChild(tip);
      const ha = Math.round(((p.v[ia] || 0) / max) * (H - 14));
      if (ha) g.appendChild(svg('rect', { x, y: H - ha, width: bw, height: ha, rx: Math.min(2, bw / 2), class: 'bar-a' }));
      if (ib >= 0) {
        const hb = Math.round(((p.v[ib] || 0) / max) * (H - 14));
        if (hb) g.appendChild(svg('rect', { x: x + bw + (bw > 2 ? 1 : 0), y: H - hb, width: bw, height: hb, rx: Math.min(2, bw / 2), class: 'bar-b' }));
      }
      g.appendChild(svg('rect', { x: x - 1, y: 0, width: Math.max(slot, 2), height: H, fill: 'transparent' }));
      s.appendChild(g);
    });
    const tf = svg('text', { x: P, y: H + 14 }); tf.textContent = pts[0].t; s.appendChild(tf);
    const tlst = svg('text', { x: W, y: H + 14, 'text-anchor': 'end' }); tlst.textContent = pts[pts.length - 1].t; s.appendChild(tlst);
    wrap.appendChild(el('div', { class: 'tl-legend' }, el('span', {}, el('i', { class: 'a', 'aria-hidden': 'true' }), labelA),
      ib >= 0 ? el('span', {}, el('i', { class: 'b', 'aria-hidden': 'true' }), labelB) : null,
      el('span', { class: 'tl-dim', text: `one bar pair per ${slotWords(tl.bucket_seconds)}, UTC` })));
    wrap.appendChild(s);
    const det = el('details', {}, el('summary', { text: 'Show as a table' }));
    det.appendChild(table(['Slot start (UTC)', labelA].concat(ib >= 0 ? [labelB] : []), pts.filter(p => (p.v[ia] || 0) || (ib >= 0 && p.v[ib])).map(p => [p.t, p.v[ia] || 0].concat(ib >= 0 ? [p.v[ib] || 0] : [])), [1, 2]));
    wrap.appendChild(det);
    return wrap;
  }
  function slotWords(sec) { return ({ 300: '5 minutes', 900: '15 minutes', 3600: 'hour', 21600: '6 hours', 86400: 'day', 604800: 'week', 2592000: '30 days' })[sec] || `${sec} seconds`; }

  // A split bar: parts [[label, count, class]] with the words beside it.
  function split(parts) {
    const total = parts.reduce((a, p) => a + (p[1] || 0), 0);
    const bar = el('div', { class: 'tl-split', role: 'img', 'aria-label': parts.map(p => `${p[0]} ${fmt(p[1])} (${pct(p[1], total)})`).join(', ') });
    for (const [label, n, cls] of parts) if (n) bar.appendChild(el('span', { class: cls, title: `${label}: ${fmt(n)}`, style: null }));
    // widths are set as properties (numbers we computed), never from log text
    Array.from(bar.children).forEach((c, i) => { const p = parts.filter(x => x[1])[i]; c.style.width = `${(p[1] / total) * 100}%`; });
    return el('div', {}, bar, el('p', { class: 'tl-dim', text: parts.map(p => `${p[0]}: ${fmt(p[1])} (${pct(p[1], total)})`).join(' · ') }));
  }

  function drawAnomalies(d) {
    const box2 = clear($('tlAnoms'));
    const items = d.anomalies || [];
    box2.appendChild(el('h3', { id: 'tlAnomH', text: `Anomalies (${items.length})` }));
    if (!items.length) { box2.appendChild(el('p', { class: 'tl-dim', text: 'Nothing stood out: no spikes, no user with many failures, no new destinations, no connector problem.' })); return; }
    for (const a of items.slice(0, 60)) {
      const kind = { spike: 'Spike', user_failures: 'Many failures for one user', new_destinations: 'New destinations', health: 'Health', user_threats: 'Threats for one user' }[a.kind] || a.kind;
      box2.appendChild(el('div', { class: 'tl-anom' }, el('strong', { text: kind + ': ' }), a.what, a.user ? el('span', { class: 'tl-dim', text: ` (${a.user})` }) : null));
    }
  }

  function drawZpa(d) {
    const root = clear($('tlZpa'));
    const z = d.zpa;
    if (!z) return;
    root.appendChild(el('h3', { id: 'tlZpaH', text: 'ZPA' }));
    const act = z.activity, st = z.status;
    const tiles = el('div', { class: 'tl-tiles' });
    if (act) {
      tiles.appendChild(tile('Connections', fmt(act.connections), `${fmt(act.records)} records`));
      tiles.appendChild(tile('Failed connections', fmt(act.failed_connections), pct(act.failed_connections, act.connections) + ' of connections'));
    }
    if (st) {
      tiles.appendChild(tile('User sessions', fmt(st.sessions), `${fmt(st.raw_session_ids)} session IDs, ${fmt(st.probes_dropped)} sign-in checks left out`));
      tiles.appendChild(tile('Users signed in', fmt(st.users), st.median_minutes != null ? `median session ${st.median_minutes} min` : ''));
      tiles.appendChild(tile('Sign-in failures', fmt(st.auth_failures), 'User Status: authentication failed'));
    }
    root.appendChild(tiles);
    const g = el('div', { class: 'tl-grid' });
    if (act) g.appendChild(box('Connections and failures over time', 'tlZpaTime', chart(z.timeline, 'connections', 'failures', 'Connections', 'Failures', 'ZPA connections')));
    if (st) g.appendChild(box('Sessions and sign-in failures over time', 'tlZpaSessTime', chart(z.timeline, 'sessions', 'auth_failures', 'Sessions started', 'Sign-in failures', 'ZPA sessions')));
    root.appendChild(g);
    if (act) {
      const rs = act.reasons || [];
      root.appendChild(box('Why connections failed', 'tlReasons',
        rs.length ? table(['Reason code', 'Kind', 'Failures', 'Users', 'What it means', 'What to do', 'Most affected'],
          rs.map(x => [x.code, x.label, x.count, x.users, x.what, x.do, (x.top_apps || []).map(a => `${a.name} (${a.count})`).join(', ')]), [2, 3])
          : el('p', { class: 'tl-dim', text: 'No failed connections in these logs.' })));
      const g2 = el('div', { class: 'tl-grid' });
      g2.appendChild(box('Top users', null, table(['User', 'Connections', 'Failures'], more(act.users, 15).map(x => [userCell(x.name), x.count, x.failures]), [1, 2])));
      g2.appendChild(box('Top applications (segments)', null, table(['Application', 'Connections', 'Failures'], more(act.apps, 15).map(x => [x.name, x.count, x.failures]), [1, 2])));
      g2.appendChild(box('Top App Connectors', null, table(['App Connector', 'Connections', 'Failures'], more(act.connectors, 15).map(x => [x.name, x.count, x.failures]), [1, 2])));
      g2.appendChild(box('Top destinations', 'tlZpaDest', table(['Host', 'Connections', 'Failures', 'Port'], more(act.destinations, 15).map(x => [destCell(x), x.count, x.failures, x.port]), [1, 2, 3])));
      g2.appendChild(box('Service Edges users came through', null, table(['Service Edge', 'Connections', 'Failures'], more(act.service_edges, 15).map(x => [x.name, x.count, x.failures]), [1, 2])));
      g2.appendChild(box('Access rules that allowed or denied', null, table(['Access rule', 'Connections'], more(act.rules, 15).map(x => [x.name, x.count]), [1])));
      root.appendChild(g2);
      if ((act.users_many_failures || []).length) root.appendChild(box('Users with many failures', null, table(['User', 'Failures', 'Connections'], act.users_many_failures.map(x => [userCell(x.name), x.failures, x.connections]), [1, 2])));
      root.appendChild(newDest(act.new_destinations, 'New ZPA destinations'));
    }
    if (st) {
      const g3 = el('div', { class: 'tl-grid' });
      g3.appendChild(box('Client types', null, table(['Client', 'Records'], (st.client_types || []).map(x => [x.name, x.count]), [1])));
      g3.appendChild(box('Platforms', null, table(['Platform', 'Sessions'], more(st.platforms, 10).map(x => [x.name, x.count]), [1])));
      g3.appendChild(box('Client Connector versions', null, table(['Version', 'Sessions'], more(st.versions, 10).map(x => [x.name, x.count]), [1])));
      g3.appendChild(box('Countries', null, table(['Country', 'Sessions'], more(st.countries, 10).map(x => [x.name, x.count]), [1])));
      if ((st.posture_misses || []).length) g3.appendChild(box('Posture checks devices failed', null, table(['Posture profile', 'Times'], more(st.posture_misses, 10).map(x => [x.name, x.count]), [1])));
      if ((st.auth_failure_users || []).length) g3.appendChild(box('Sign-in failures by user', null, table(['User', 'Failures'], more(st.auth_failure_users, 10).map(x => [userCell(x.name), x.count]), [1])));
      root.appendChild(g3);
      if ((st.rows || []).length) root.appendChild(sessions(st));
    }
  }

  function sessions(st) {
    const out = box(`Sessions (${fmt(st.rows_total)}${st.rows_total > st.rows.length ? `, newest ${fmt(st.rows.length)} kept` : ''})`, 'tlSessions');
    const input = el('input', { type: 'search', id: 'tlSessFilter', maxlength: '200', placeholder: 'user, device, address, country…' });
    // Exact-value filters from the sessions themselves (the log's own words, set as text).
    const pick = (id, key, label) => {
      const vals = Array.from(new Set(st.rows.map(r => String(r[key] || '')))).sort();
      const sel = el('select', { id }, el('option', { value: '', text: `Any ${label.toLowerCase()}` }),
        ...vals.map(v => el('option', { value: v, text: v || '(not in the log)' })));
      sel.value = vals.includes(sessFilter[key]) ? sessFilter[key] : '';
      sessFilter[key] = sel.value;
      return sel;
    };
    const ver = pick('tlSessVersion', 'version', 'Client Connector version');
    const plat = pick('tlSessPlatform', 'platform', 'Platform');
    out.appendChild(el('div', { class: 'tl-row' }, el('label', { for: 'tlSessFilter', text: 'Find sessions' }), input,
      el('label', { for: 'tlSessVersion', text: 'Client Connector version' }), ver, el('label', { for: 'tlSessPlatform', text: 'Platform' }), plat));
    const holder = el('div');
    out.appendChild(holder);
    const cols = ['User', 'Start', 'End', 'Minutes', 'Public IP', 'Device', 'Platform', 'Version', 'Country', 'Trusted network'];
    const draw = () => {
      const q = input.value.trim().toLowerCase();
      sessFilter.version = ver.value; sessFilter.platform = plat.value;
      const rows = st.rows.filter(r => (!ver.value || String(r.version || '') === ver.value) && (!plat.value || String(r.platform || '') === plat.value))
        .filter(r => !q || [r.user, r.device, r.public_ip, r.private_ip, r.country, r.city, r.platform, r.version].some(v => String(v || '').toLowerCase().includes(q)));
      clear(holder).appendChild(table(cols, rows.slice(0, 200).map(r => [r.user, r.start, r.end || 'still open', r.duration_s == null ? '' : Math.round(r.duration_s / 6) / 10,
        r.public_ip, r.device, r.platform, r.version, r.country, r.trusted_network || 'no']), [3]));
      holder.appendChild(el('p', { class: 'tl-dim', text: `${fmt(rows.length)} matching${rows.length > 200 ? ', first 200 shown; the Excel download has them all' : ''}.`
        + (ver.value || plat.value ? ' Downloads with user names keep only the sessions of the version and platform picked here.' : '') }));
    };
    input.addEventListener('input', draw);
    ver.addEventListener('change', draw);
    plat.addEventListener('change', draw);
    draw();
    return out;
  }

  function newDest(nd, title) {
    if (!nd) return el('span');
    if (!nd.computed) return box(title, null, el('p', { class: 'tl-dim', text: nd.why }));
    return box(`${title} (${fmt(nd.total)} since ${nd.since})`, null, nd.items.length
      ? table(['Destination', 'First seen', 'Count'], nd.items.map(x => [destCell(x), x.first_seen, x.count]), [2])
      : el('p', { class: 'tl-dim', text: 'None: every destination in the last part of the logs was seen before.' }));
  }

  function drawHealth(d) {
    const root = clear($('tlHealth'));
    const h = d.health;
    if (!h) return;
    root.appendChild(el('h3', { id: 'tlHealthH', text: 'App Connector and Service Edge health' }));
    for (const [key, title] of [['connectors', 'App Connectors'], ['service_edges', 'Private Service Edges']]) {
      const part = h[key];
      if (!part) continue;
      root.appendChild(box(`${title}: ${fmt(part.count)}, ${fmt(part.down)} down or failing at the end of the logs`, null,
        table(['Name', 'Group', 'State', 'Disconnects', 'Failed sign-ins', 'Last seen', 'Versions', 'Max CPU %', 'Max memory %', 'Notes'],
          part.rows.map(r => [r.name, r.group, el('span', { class: `tl-chip ${r.state}`, text: r.state }), r.disconnected, r.auth_failed, r.last_seen,
            (r.versions || []).join(', '), r.cpu_max, r.mem_max, (r.notes || []).join('; ') || 'nothing to note']), [3, 4, 7, 8])));
    }
  }

  function drawZia(d) {
    const root = clear($('tlZia'));
    const z = d.zia;
    if (!z) return;
    root.appendChild(el('h3', { id: 'tlZiaH', text: 'ZIA' }));
    const p = d.period || {};
    if (p.first && p.last) {
      const from = Date.parse(p.first), to = Date.parse(p.last);
      if (Number.isFinite(from) && Number.isFinite(to)) {
        const q = new URLSearchParams({ from: String(from), to: String(Math.max(to, from + 3600000)) });
        root.appendChild(el('p', { class: 'tl-dim' }, 'Traffic insights reads ZIA\'s own counts for a window; these logs add what it cannot: per rule, per category, per user and per host. ',
          el('a', { class: 'tl-link', id: 'tlInsights', href: '/report/insights?' + q.toString(), target: '_blank', rel: 'noopener', text: 'Open Traffic insights for the same window' })));
      }
    }
    for (const k of ['zia_web', 'zia_fw', 'zia_dns']) {
      const x = z[k];
      if (!x) continue;
      const sec = el('div', { id: 'tl_' + k });
      sec.appendChild(el('h3', { text: `${x.label}: ${fmt(x.records)} records` }));
      const a = x.actions || {};
      sec.appendChild(split([['Allowed', a.allowed || 0, 'ok'], ['Blocked', a.blocked || 0, 'bad'], ['Cautioned', a.cautioned || 0, 'mid'], ['Isolated', a.isolated || 0, 'mid'], ['Other or not logged', (a.other || 0) + (a.unknown || 0), 'unk']]));
      const g = el('div', { class: 'tl-grid' });
      g.appendChild(box('All against blocked over time', null, chart(z.timeline, k + ':all', k + ':blocked', 'All', 'Blocked', x.label)));
      g.appendChild(box('Rules hit', null, x.rules.length ? table(['Module', 'Rule', 'Action', 'Count'], more(x.rules, 20).map(r => [r.module, r.rule, r.action, r.count]), [3])
        : el('p', { class: 'tl-dim', text: 'No rule names in these logs (a web feed names the rule only for blocks unless the URL filtering and Cloud App Control rule fields are in the feed).' })));
      if (k !== 'zia_fw') g.appendChild(box(k === 'zia_dns' ? 'Top domain categories' : 'Top URL categories', null, table(['Category', 'Count', 'Blocked'], more(x.categories, 15).map(c => [c.name, c.count, c.blocked]), [1, 2])));
      g.appendChild(box('Top destinations', null, table(['Destination', 'Count', 'Blocked'], more(x.destinations, 15).map(c => [destCell(c), c.count, c.blocked]), [1, 2])));
      g.appendChild(box('Top users', null, table(['User', 'Count', 'Blocked'], more(x.users, 15).map(c => [userCell(c.name), c.count, c.blocked]), [1, 2])));
      if ((x.apps || []).length) g.appendChild(box(k === 'zia_fw' ? 'Network applications and services' : 'Cloud applications', null, table(['Name', 'Count'], more(x.apps, 15).map(c => [c.name, c.count]), [1])));
      if ((x.block_reasons || []).length) g.appendChild(box('Why transactions were blocked', null, table(['Reason', 'Count'], more(x.block_reasons, 15).map(c => [c.name, c.count]), [1])));
      if (x.dlp) {
        const dl = x.dlp;
        g.appendChild(box(`DLP events: ${fmt(dl.events)}`, null, dl.events ? el('div', {},
          table(['Engine or dictionary', 'Count'], more(dl.engines, 10).map(c => ['Engine: ' + c.name, c.count]).concat(more(dl.dictionaries, 10).map(c => ['Dictionary: ' + c.name, c.count])), [1]),
          el('p', { class: 'tl-dim', text: 'By action: ' + Object.entries(dl.actions || {}).map(([k2, v]) => `${k2} ${fmt(v)}`).join(', ') }))
          : el('p', { class: 'tl-dim', text: 'No DLP engine, dictionary or rule in these records.' })));
      }
      const th = x.threats;
      g.appendChild(box(`Threat events: ${fmt(th.events)}`, null, th.events ? el('div', {},
        table(['Threat', 'Count'], more(th.names, 10).map(c => [c.name, c.count]), [1]),
        el('p', { class: 'tl-dim', text: 'By action: ' + Object.entries(th.actions || {}).map(([k2, v]) => `${k2} ${fmt(v)}`).join(', ') }))
        : el('p', { class: 'tl-dim', text: 'No threat name in these records.' })));
      if (x.ssl) {
        const s = x.ssl;
        const known = s.inspected + s.not_inspected;
        g.appendChild(box('SSL inspected or not', null, known ? el('div', {},
          split([['Inspected', s.inspected, 'ok'], ['Not inspected', s.not_inspected, 'bad'], ['Plain HTTP', s.plain_http, 'unk']]),
          report && report.report_id ? el('p', {}, el('a', { class: 'rp-btn', id: 'tlTrueCoverage', target: '_blank', rel: 'noopener',
            href: `/report/sslcoverage?logs=${encodeURIComponent(report.report_id)}` }, 'True inspection coverage from these logs'),
            el('span', { class: 'tl-dim', text: ' Opens SSL coverage, which ties each line left encrypted to the SSL rule behind it.' })) : null,
          s.reasons.length ? table(['Why not inspected', 'Count'], more(s.reasons, 10).map(c => [c.name, c.count]), [1]) : null,
          s.destinations_not_inspected.length ? table(['Not inspected: destination', 'Count'], more(s.destinations_not_inspected, 10).map(c => [destCell(Object.assign({ link: /^[A-Za-z0-9.*_-]+\.[A-Za-z0-9.-]+$/.test(c.name) }, c)), c.count]), [1]) : null)
          : el('p', { class: 'tl-dim', text: 'These records do not say whether SSL was inspected (add the SSL Inspected field, ssldecrypted, to the feed).' })));
      }
      sec.appendChild(g);
      sec.appendChild(newDest(x.new_destinations, `New ${x.label} destinations`));
      root.appendChild(sec);
    }
  }

  function drawNav() {
    const nav = clear($('tlNav'));
    const links = [['tlAnomH', 'Anomalies'], ['tlZpaH', 'ZPA'], ['tlReasons', 'Why connections failed'], ['tlSessions', 'Sessions'], ['tlHealthH', 'Health'],
      ['tl_zia_web', 'ZIA web'], ['tl_zia_fw', 'ZIA firewall'], ['tl_zia_dns', 'ZIA DNS'], ['tlSiemH', 'SIEM queries']];
    for (const [id, label] of links) if ($(id)) nav.appendChild(el('a', { class: 'rp-btn', href: '#' + id, text: label }));
  }

  // ── Downloads, save, forget ──
  async function download(fmtName) {
    if (!report) return;
    const names = $('tlNames').checked ? '1' : '0';
    try {
      const q = new URLSearchParams({ format: fmtName, names, version: sessFilter.version, platform: sessFilter.platform });
      const r = await fetch(`/api/traffic-logs/report/${encodeURIComponent(report.report_id)}/export?${q.toString()}`);
      if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || `HTTP ${r.status}`); }
      const blob = await r.blob();
      const cd = r.headers.get('Content-Disposition') || '';
      const m = /filename=([A-Za-z0-9_.-]+)/.exec(cd);
      const a = el('a', { href: URL.createObjectURL(blob), download: m ? m[1] : `traffic_logs.${fmtName}` });
      document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
      status(`Downloaded (${names === '1' ? 'with user names and addresses' : 'counts only'}).`);
    } catch (e) { status(`Could not download: ${e.message}`, true); }
  }
  $('tlCsv').addEventListener('click', () => download('csv'));
  $('tlXlsx').addEventListener('click', () => download('xlsx'));
  $('tlPdf').addEventListener('click', () => download('pdf'));

  $('tlSave').addEventListener('click', async () => {
    if (!report) return;
    const title = (window.prompt('A name for this report (kept on this computer only):', 'Traffic and session logs') || '').slice(0, 80);
    try {
      const r = await fetch(`/api/traffic-logs/report/${encodeURIComponent(report.report_id)}/save`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, names: $('tlNames').checked }) });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
      status(`Saved on this computer${data.saved && data.saved.names ? ' with user names and addresses' : ', counts only'}.`);
      announce('Report saved');
      loadSaved();
    } catch (e) { status(`Could not save: ${e.message}`, true); }
  });

  $('tlForget').addEventListener('click', async () => {
    if (!report) return;
    try { await fetch(`/api/traffic-logs/report/${encodeURIComponent(report.report_id)}`, { method: 'DELETE' }); } catch (e) { /* the page forgets it anyway */ }
    report = null;
    ['tlZpa', 'tlHealth', 'tlZia', 'tlAnoms', 'tlSummary', 'tlNotes', 'tlNav'].forEach(id => clear($(id)));
    $('tlResults').hidden = true;
    ['tlCsv', 'tlXlsx', 'tlPdf', 'tlSave', 'tlForget'].forEach(id => setEnabled(id, false));
    status('Forgotten: the analysis is gone from this page and from the server\'s memory.');
    announce('Analysis forgotten');
  });

  async function loadSaved() {
    const list = $('tlSaved');
    try {
      const r = await fetch('/api/traffic-logs/saved');
      const data = await r.json();
      clear(list);
      if (!(data.reports || []).length) { list.appendChild(el('li', { class: 'tl-dim', text: 'None saved yet.' })); return; }
      for (const x of data.reports) {
        list.appendChild(el('li', {}, el('strong', { text: x.title }), ` ${x.at || ''} · ${x.records == null ? '?' : fmt(x.records)} records · ${x.names ? 'with names' : 'counts only'} `,
          el('button', { type: 'button', class: 'tl-act', 'aria-label': `Open saved report ${x.title} from ${x.at}`, text: 'Open', on: { click: () => openSaved(x.name) } }),
          el('button', { type: 'button', class: 'tl-act', 'aria-label': `Delete saved report ${x.title} from ${x.at}`, text: 'Delete', on: { click: () => deleteSaved(x.name, x.title) } })));
      }
    } catch (e) { clear(list).appendChild(el('li', { class: 'tl-dim', text: 'Could not list the saved reports.' })); }
  }
  async function openSaved(name) {
    try {
      const r = await fetch(`/api/traffic-logs/saved/${encodeURIComponent(name)}/open`, { method: 'POST' });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
      show(data);
      status('Opened the saved report.');
    } catch (e) { status(`Could not open: ${e.message}`, true); }
  }
  async function deleteSaved(name, title) {
    if (!window.confirm(`Delete the saved report "${title}" from this computer?`)) return;
    try {
      const r = await fetch(`/api/traffic-logs/saved/${encodeURIComponent(name)}`, { method: 'DELETE' });
      if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || `HTTP ${r.status}`); }
      status('Deleted.');
      loadSaved();
    } catch (e) { status(`Could not delete: ${e.message}`, true); }
  }

  // ── Daily report from a watched folder (opt-in) ──
  async function api(method, url, body) {
    const r = await fetch(url, { method, headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) {
      const x = d && d.detail;
      throw new Error(typeof x === 'string' ? x : Array.isArray(x) && x.length ? x.map(e => String((e && e.msg) || e)).join('; ') : `HTTP ${r.status}`);
    }
    return d;
  }
  function watchShow(st) {
    const s = st.settings || {};
    $('tlwFolder').value = s.folder || ''; $('tlwHour').value = String(s.hour == null ? 6 : s.hour); $('tlwKeep').value = String(s.keep || 7);
    $('tlwNames').checked = !!s.names; $('tlwOn').checked = !!s.enabled;
    const l = st.limits || {};
    $('tlwLimits').textContent = `At most ${fmt(l.files)} files, ${fmt(l.file_mb)} MB each and ${fmt(l.total_mb)} MB together a run (${(l.extensions || []).join(' ')}).`;
    const last = st.last_run;
    const parts = [s.enabled ? `On: next report ${st.next_run || 'when the folder is set'}.` : 'Off.'];
    if (last) parts.push(`Last report ${last.at} (${last.trigger === 'manual' ? 'made by hand' : 'scheduled'}): ${last.status}${last.files ? `, ${fmt(last.files)} file(s), ${fmt(last.records)} records` : ''}${last.error ? ` — ${last.error}` : ''}${last.report ? ', in Saved reports' : ''}.`);
    $('tlwStatus').textContent = parts.join(' ');
    $('tlwStatus').classList.toggle('bad', !!(last && last.status === 'failed'));
  }
  function watchBody() {
    return { folder: $('tlwFolder').value.trim(), hour: parseInt($('tlwHour').value, 10), keep: parseInt($('tlwKeep').value, 10),
      names: $('tlwNames').checked, enabled: $('tlwOn').checked };
  }
  api('GET', '/api/traffic-logs/watch').then(watchShow).catch(() => { $('tlwStatus').textContent = 'Could not read the daily report settings.'; });
  $('tlwSave').addEventListener('click', async () => {
    try { watchShow(await api('POST', '/api/traffic-logs/watch', watchBody())); announce('Daily report settings saved'); }
    catch (e) { $('tlwStatus').textContent = `Not saved: ${e.message}`; $('tlwStatus').classList.add('bad'); }
  });
  $('tlwRun').addEventListener('click', async () => {
    $('tlwStatus').textContent = 'Reading the folder…';
    try { const d = await api('POST', '/api/traffic-logs/watch/run'); watchShow(d.state); loadSaved(); }
    catch (e) { $('tlwStatus').textContent = `No report: ${e.message}`; $('tlwStatus').classList.add('bad'); }
  });

  // ── Syslog listener (off by default) ──
  let syslogTimer = null;
  function syslogShow(st) {
    const on = !!st.running;
    setEnabled('tlsStart', !on); setEnabled('tlsStop', on);
    setEnabled('tlsAnalyze', (st.lines || 0) > 0); setEnabled('tlsClear', (st.lines || 0) > 0);
    const l = st.limits || {};
    $('tlsLimits').textContent = `Messages over ${fmt(l.message_bytes)} bytes, more than ${fmt(l.rate_per_second)} a second, or past ${fmt(l.lines)} lines (${fmt(l.buffer_mb)} MB) are dropped and counted.`;
    const c = st.counts || {};
    $('tlsStatus').textContent = on || st.lines
      ? `${on ? `Listening on ${st.host} port ${st.port} (${String(st.protocol || '').toUpperCase()})` : 'Stopped'}: ${fmt(st.lines || 0)} line(s) in memory from ${fmt(st.senders || 0)} sender(s). `
        + `Received ${fmt(c.received || 0)}, dropped ${fmt((c.too_long || 0) + (c.rate_limited || 0) + (c.buffer_dropped || 0))} (too long ${fmt(c.too_long || 0)}, too fast ${fmt(c.rate_limited || 0)}, buffer full ${fmt(c.buffer_dropped || 0)}).`
      : 'Not listening.';
    clearTimeout(syslogTimer);
    if (on) syslogTimer = setTimeout(syslogRefresh, 3000);
  }
  function syslogRefresh() { api('GET', '/api/traffic-logs/syslog').then(syslogShow).catch(() => {}); }
  syslogRefresh();
  $('tlsStart').addEventListener('click', async () => {
    try {
      syslogShow(await api('POST', '/api/traffic-logs/syslog/start', { host: $('tlsHost').value.trim(), port: parseInt($('tlsPort').value, 10),
        protocol: $('tlsProto').value, allow_remote: $('tlsRemote').checked }));
      announce('Syslog listener started');
    } catch (e) { $('tlsStatus').textContent = `Not started: ${e.message}`; }
  });
  $('tlsStop').addEventListener('click', async () => {
    try { syslogShow(await api('POST', '/api/traffic-logs/syslog/stop', { clear: false })); announce('Syslog listener stopped'); }
    catch (e) { $('tlsStatus').textContent = `Could not stop: ${e.message}`; }
  });
  $('tlsClear').addEventListener('click', async () => {
    try { syslogShow(await api('POST', '/api/traffic-logs/syslog/clear')); announce('Lines forgotten'); }
    catch (e) { $('tlsStatus').textContent = `Could not clear: ${e.message}`; }
  });
  $('tlsAnalyze').addEventListener('click', async () => {
    try { show(await api('POST', '/api/traffic-logs/syslog/analyze')); status('Analysed the lines the listener received.'); }
    catch (e) { status(`Could not analyse: ${e.message}`, true); }
  });

  // ── SIEM queries ──
  function syncSourcePlaceholders() {
    const siem = $('tlSiem').value;
    const d = (info && info.siem && info.siem.default_source && info.siem.default_source[siem]) || {};
    $('tlSrcZpa').placeholder = d.zpa || ''; $('tlSrcWeb').placeholder = d.zia_web || '';
    $('tlSrcFw').placeholder = d.zia_fw || ''; $('tlSrcDns').placeholder = d.zia_dns || '';
  }
  async function renderQuery() {
    const qid = $('tlQuestion').value;
    if (!qid) return;
    const p = new URLSearchParams({ siem: $('tlSiem').value, question: qid, hours: String(parseInt($('tlHours').value, 10) || 24),
      user: $('tlQUser').value, destination: $('tlQDest').value, src_zpa: $('tlSrcZpa').value, src_web: $('tlSrcWeb').value,
      src_fw: $('tlSrcFw').value, src_dns: $('tlSrcDns').value });
    try {
      const r = await fetch('/api/traffic-logs/siem?' + p.toString());
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
      const q = (data.queries || [])[0];
      $('tlQuery').value = q ? q.query : '';
      $('tlQStatus').textContent = q && q.filtered ? 'Filtered to the user or destination you typed.' : '';
    } catch (e) { $('tlQuery').value = ''; $('tlQStatus').textContent = `Could not write the query: ${e.message}`; }
  }
  const later = () => { clearTimeout(siemTimer); siemTimer = setTimeout(renderQuery, 250); };
  $('tlSiem').addEventListener('change', () => { syncSourcePlaceholders(); renderQuery(); });
  $('tlQuestion').addEventListener('change', renderQuery);
  ['tlHours', 'tlQUser', 'tlQDest', 'tlSrcZpa', 'tlSrcWeb', 'tlSrcFw', 'tlSrcDns'].forEach(id => $(id).addEventListener('input', later));
  $('tlCopyQuery').addEventListener('click', async () => {
    const text = $('tlQuery').value;
    if (!text) return;
    try { await navigator.clipboard.writeText(text); $('tlQStatus').textContent = 'Query copied.'; announce('Query copied to the clipboard'); }
    catch (e) { $('tlQuery').select(); $('tlQStatus').textContent = 'Select the text and copy it with Ctrl+C.'; }
  });
})();
