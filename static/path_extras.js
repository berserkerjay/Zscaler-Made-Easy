// ── Path analyzer: a picked device, two identities compared, Test from here ──
// The panels are in the page (report_path.html: #paDevice, #paCompare);
// this file holds what they do and what the result shows:
//
// * Device: look a user's enrolled devices up in the Client Connector
//   Portal (POST /api/path-analyzer/devices, only with ZCC ticked on the
//   Scope page) and pick one (POST /api/path-analyzer/devices/detail). The
//   analysis then uses that device's platform, the app profile the Portal
//   reports for it and what the Portal says about it (path_device.py).
//   PathExtras.device() is what the page adds to its start request.
// * Compare: the same destination for identity A (the what-if and device
//   above) and identity B (this panel), on one tenant read
//   (POST /api/path-analyzer/compare/start, path_compare.py); each step
//   side by side, the step where they diverge marked; CSV and JSON.
// * Test from here: after a result, one explicit click tests the
//   destination from the computer running this app (DNS, TCP, TLS;
//   POST /api/path-analyzer/test-from-here, path_probe.py) and compares it
//   with the prediction. Nothing is kept: not on the server, not in this
//   browser's storage.
// * Manual inputs (#paManual): a pasted PAC and typed VPN gateways and
//   Z-Tunnel 2.0 lists, sent as `whatif_bypass` (path_manual.py checks them
//   before sign-in). The result's "Manual inputs (what-if)" block says what
//   they would do, on their own or added to the tenant's app profiles.
//   PathExtras.manual() is what the page adds to its start request; nothing
//   typed is kept.
//
// Every value is escaped before it is drawn. Nothing here writes to the tenant.
(function () {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const errText = (d, status) => { const x = d && d.detail; if (typeof x === 'string' && x) return x; if (x && typeof x === 'object' && !Array.isArray(x) && (x.cause || x.message)) return String(x.cause || x.message);
    return Array.isArray(x) && x.length ? `The request was not accepted: ${x.slice(0, 3).map(e => String((e && e.msg) || e)).join('; ')}.` : `HTTP ${status}`; };
  let page = { credBody: () => ({}), scopeSelection: () => ({ scopes: [], channels: {}, from_page: false }), traffic: () => ({}),
    destination: () => '', network: () => 'off', platform: () => 'windows', reportId: () => '', say: () => {} };
  const zccInScope = () => (page.scopeSelection().scopes || []).includes('zcc');
  const post = async (url, body, headers) => {
    const r = await fetch(url, { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}), body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(errText(d, r.status));
    return d;
  };
  // Plain words for a step's outcome (a module verdict or a hop status).
  const WORDS = { pass: 'Forwarded', bypass: 'Bypassed', bypassed: 'Bypassed', block: 'Blocked', blocked: 'Blocked', allow: 'Allowed', decrypt: 'Decrypted',
    not_decrypted: 'Not decrypted', inspect: 'Inspected', caution: 'Caution', isolate: 'Isolated', none: 'No rule', not_reached: 'Not reached',
    not_applicable: 'Not applicable', out_of_scope: 'Not in scope', unknown: 'Unknown', warn: 'Weak', blind: 'Encrypted, not seen', enforce: 'Enforced',
    monitor: 'Monitored', not_matched: 'No match', matched: 'Matched', conditional: 'Depends', zpa_allowed: 'Carried by ZPA', zpa_denied: 'Blocked by ZPA',
    'not on this path': 'Not on this path' };
  const word = w => WORDS[w] || String(w || '').replace(/_/g, ' ');

  // ── A device picker (A in #paDevice, B in #paCompare) ───────────────
  const CLEAR_ID = { paDev: 'paDevClear', paCmpDev: 'paCmpDevClear' };   // the "Clear the device" buttons
  function picker(p) {
    const st = { ref: '', found: [], chosen: null };
    const el = id => document.getElementById(p + id);
    const live = t => { const l = el('Live'); if (l) { l.textContent = ''; setTimeout(() => { l.textContent = t; }, 30); } };
    function refresh() {
      const ok = zccInScope();
      const b = el('Find'); if (b) b.disabled = !ok;
      const h = el('Scope');
      if (h) h.textContent = ok ? 'Find devices asks the Client Connector Portal once for this user’s devices (at most 20); Use this device reads that one device’s details. Nothing else is read.'
        : 'Looking devices up needs Client Connector (ZCC) ticked on the Scope page and a OneAPI sign-in.';
    }
    function line(d) {
      return [d.hostname || 'unnamed device', d.platform_label !== 'unknown' ? d.platform_label : '', d.os_version, d.version ? `Client Connector ${d.version}` : '',
        d.profile ? `profile “${d.profile}”` : 'profile not reported'].filter(Boolean).join(' · ');
    }
    async function find() {
      const q = (el('Q').value || '').trim();
      const list = el('Res');
      if (q.length < 2) { live('Type at least 2 characters of the user’s sign-in name.'); el('Q').focus(); return; }
      const b = el('Find'); b.disabled = true; b.textContent = 'Finding…';
      try {
        const d = await post('/api/path-analyzer/devices', Object.assign({}, page.credBody(), page.scopeSelection(), { device_user: q }));
        st.ref = d.ref; st.found = d.devices || [];
        list.hidden = false;
        if (d.error) { list.innerHTML = `<li class="df-hint">${E(d.error)}</li>`; live(`The lookup failed: ${d.error}`); return; }
        if (!st.found.length) { list.innerHTML = `<li class="df-hint">No enrolled device whose user contains “${E(q)}”.</li>`; live('No device found.'); return; }
        list.innerHTML = st.found.map((x, i) => `<li><button type="button" class="rp-btn" data-dev-pick="${i}">${E(line(x))}<span class="df-by">${E(x.user)}</span></button></li>`).join('')
          + (d.capped ? `<li class="df-hint">Showing the first ${E(d.limit)}; type more of the name to narrow it.</li>` : '');
        live(`${st.found.length} device(s) found. Choose one.`);
        const first = list.querySelector('button'); if (first) first.focus();
      } catch (e) {
        list.hidden = false; list.innerHTML = `<li class="df-hint">${E(e.message)}</li>`; live(`The lookup could not run: ${e.message}`);
      } finally { b.textContent = 'Find devices'; refresh(); }
    }
    async function pick(i) {
      const x = st.found[i]; if (!x) return;
      const list = el('Res');
      live(`Reading ${x.hostname || 'the device'}’s details…`);
      let dev = x;
      try { dev = (await post('/api/path-analyzer/devices/detail', Object.assign({}, page.credBody(), page.scopeSelection(), { ref: st.ref, device_id: x.id }))).device || x; }
      catch (e) { dev = Object.assign({}, x, { details: { status: 'failed', reason: e.message } }); }
      st.chosen = dev; list.hidden = true; list.innerHTML = '';
      draw(); live(`${dev.hostname || 'The device'} chosen: the analysis uses its platform and app profile.`);
      if (p === 'paDev') syncPlatform();
      const c = document.getElementById(CLEAR_ID[p]); if (c) c.focus();
    }
    function clear() {
      st.chosen = null; draw(); if (p === 'paDev') syncPlatform(); live('Device cleared: the platform you choose applies again.'); el('Q').focus();
    }
    function draw() {
      const box = el('Chosen'); if (!box) return;
      const d = st.chosen;
      box.hidden = !d;
      if (!d) { box.innerHTML = ''; return; }
      const det = d.details || {};
      const detLine = det.status === 'read' ? `ZIA ${E(det.zia)}, ZPA ${E(det.zpa)}${det.device_trust ? `, device trust ${E(det.device_trust)}` : ''}`
        : det.status === 'failed' ? `details not read: ${E(det.reason)}` : 'details not read yet';
      box.innerHTML = `<div class="pa-dev-card"><div class="df-hop-h"><span class="df-chip st-ok">Device</span><strong>${E(d.hostname || 'unnamed device')}</strong><span class="df-by">${E(d.user)}</span></div>
        <div class="df-hop-d">${E(line(d))}</div><div class="df-hop-d">${detLine}</div>
        <p><button type="button" class="rp-btn" id="${CLEAR_ID[p]}">Clear the device</button></p></div>`;
      document.getElementById(CLEAR_ID[p]).addEventListener('click', clear);
    }
    function init() {
      const f = el('Find'); if (!f) return;
      f.addEventListener('click', find);
      el('Q').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); find(); } });
      el('Res').addEventListener('click', e => { const b = e.target.closest('[data-dev-pick]'); if (b) pick(Number(b.dataset.devPick)); });
      refresh();
    }
    return { init, refresh, value: () => (st.chosen ? { ref: st.ref, id: st.chosen.id } : {}), chosen: () => st.chosen };
  }
  const devA = picker('paDev'), devB = picker('paCmpDev');
  function syncPlatform() {
    const sel = document.getElementById('paPlat'); if (!sel) return;
    const d = devA.chosen();
    sel.disabled = !!d;
    const note = document.getElementById('paPlatFrom');
    if (note) { note.hidden = !d; note.textContent = d ? `Platform from the picked device: ${d.platform_label}` : ''; }
    if (d && d.platform) sel.value = d.platform;
  }

  // ── The device in the result ──────────────────────────────────────
  function deviceSection(dev) {
    if (!dev) return '';
    const ap = dev.app_profile || {}, fp = dev.forwarding_profile || {};
    const facts = (dev.facts || []).map(f => `<tr><th scope="row">${E(f.label)}</th><td>${f.known ? E(f.value) : '<span class="pa-unknown">unknown</span>'}</td><td class="df-by">${E(f.source)}</td></tr>`).join('');
    return `<section class="pa-device-out" id="paDeviceOut" aria-labelledby="paDevOutH">
      <h2 class="df-h" id="paDevOutH">The device: ${E(dev.hostname || 'picked device')}</h2>
      <div class="pa-facts">
        <span class="df-prof"><span class="k">App profile applied</span><span class="v">${E(ap.applied || ap.reported || 'unknown')}</span></span>
        <span class="df-prof"><span class="k">Forwarding profile</span><span class="v">${E(fp.name || '—')}${fp.mode ? ` (${E(fp.mode)})` : ''}</span></span>
        <span class="df-prof"><span class="k">Network</span><span class="v">${E((dev.network || {}).value)} (your choice)</span></span>
      </div>
      <p class="df-hop-d"><strong>Why this profile:</strong> ${E(ap.why)}</p>
      <p class="df-hop-d"><strong>Forwarding:</strong> ${E(fp.why)}</p>
      <p class="df-hint">${E((dev.network || {}).why)} ${E((dev.posture || {}).why)}</p>
      <div class="df-tablewrap"><table class="df-table pa-dev-facts"><caption class="sr-only">What the Client Connector Portal says about the device, and where each fact came from</caption>
        <thead><tr><th scope="col">Fact</th><th scope="col">Value</th><th scope="col">Source</th></tr></thead><tbody>${facts}</tbody></table></div>
    </section>`;
  }

  // ── Compare two identities ────────────────────────────────────────
  const B_FIELDS = ['user', 'group', 'department', 'location'];
  let cmpJob = null, cmpRunning = false;
  function identityB() {
    const out = {};
    B_FIELDS.forEach(k => { const el = document.getElementById(`paCmp_${k}`); const v = el ? el.value.trim().slice(0, 200) : ''; if (v) out[k] = v; });
    return out;
  }
  async function follow(jobId, onLog) {
    let next = 0, misses = 0; const logs = [];
    for (;;) {
      await new Promise(res => setTimeout(res, 1000));
      let snap;
      try {
        const r = await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(jobId)}?since=${next}`, { cache: 'no-store' });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        snap = await r.json(); misses = 0;
      } catch (e) { if (++misses >= 20) throw new Error(`Lost contact with the app (${e.message}).`); continue; }
      logs.push(...(snap.logs || [])); next = snap.next; onLog(logs);
      if (snap.status !== 'running') return Object.assign({}, snap, { logs });
    }
  }
  async function compareRun() {
    if (cmpRunning) return;
    const out = document.getElementById('paCmpOut');
    const dest = page.destination();
    if (!dest) { out.innerHTML = '<div class="bp-card risk"><div class="t">Nothing to compare</div><div>Type a destination in the bar above first.</div></div>'; document.getElementById('paDest').focus(); return; }
    const btn = document.getElementById('paCmpRun');
    cmpRunning = true; btn.disabled = true; btn.textContent = 'Comparing…';
    out.innerHTML = `<div class="pa-live"><div class="pa-live-h"><span class="spin" aria-hidden="true"></span><strong>Comparing A and B for ${E(dest)}</strong><span class="sep"></span><button type="button" class="rp-btn" id="paCmpStop">Stop</button></div>
      <div class="pa-log pa-log-live" id="paCmpLog" role="log" aria-live="polite" aria-label="What the comparison is doing">Connecting to the tenant…</div></div>`;
    document.getElementById('paCmpStop').addEventListener('click', async () => {
      const s = document.getElementById('paCmpStop'); if (s) { s.disabled = true; s.textContent = 'Stopping…'; }
      if (cmpJob) { try { await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(cmpJob)}/cancel`, { method: 'POST' }); } catch (e) { /* the poll shows it */ } }
    });
    page.say(`Comparing A and B for ${dest}.`);
    try {
      const payload = Object.assign({}, page.credBody(), page.scopeSelection(), page.traffic(),
        { destination: dest, network: page.network(), platform: page.platform(), report_id: page.reportId(), device: devA.value(), identity_b: identityB(), device_b: devB.value() });
      const d = await post('/api/path-analyzer/compare/start', payload);
      cmpJob = d.job_id;
      const snap = await follow(cmpJob, logs => { const l = document.getElementById('paCmpLog'); if (l) { l.textContent = logs.join('\n'); l.scrollTop = l.scrollHeight; } });
      if (snap.status !== 'done' || !snap.result || snap.result.stopped) throw new Error(snap.error || (snap.result && snap.result.stopped) || 'The comparison did not finish.');
      drawCompare(snap.result, cmpJob);
      page.say(snap.result.headline);
    } catch (e) {
      out.innerHTML = `<div class="bp-card risk"><div class="t">The comparison could not run</div><div>${E(e.message)}</div></div>`;
      page.say(`The comparison could not run: ${e.message}`);
    } finally { cmpRunning = false; btn.disabled = false; btn.textContent = 'Compare A and B'; }
  }
  function cell(s) {
    return `<span class="pa-cmp-o">${E(word(s.outcome))}</span>${s.rule ? `<br><code>${E(s.rule)}</code>` : ''}`;
  }
  function drawCompare(res, jobId) {
    const out = document.getElementById('paCmpOut');
    const rows = (res.steps || []).map(s => `<tr class="${s.first ? 'pa-cmp-first' : s.differs && s.key !== 'platform' ? 'pa-cmp-diff' : ''}">
        <th scope="row">${E(s.label)}${s.first ? ' <span class="df-chip st-warn">Paths diverge here</span>' : s.differs && s.key !== 'platform' ? ' <span class="df-chip">Differs</span>' : ''}</th>
        <td>${cell(s.a)}</td><td>${cell(s.b)}</td></tr>`).join('');
    out.innerHTML = `<section class="pa-cmp-out" aria-labelledby="paCmpH">
      <p class="pa-cmp-headline" id="paCmpH"><strong>${E(res.headline)}</strong></p>
      <div class="pa-facts">
        <span class="df-prof"><span class="k">A</span><span class="v">${E((res.a || {}).label)}: ${E((res.a || {}).headline)}</span></span>
        <span class="df-prof"><span class="k">B</span><span class="v">${E((res.b || {}).label)}: ${E((res.b || {}).headline)}</span></span>
      </div>
      <p class="pa-cmp-tools"><button type="button" class="rp-btn" id="paCmpCsv">CSV</button><button type="button" class="rp-btn" id="paCmpJson">JSON</button>
        <span class="df-hint">${E(res.differences)} step(s) differ.</span></p>
      <div class="df-tablewrap"><table class="df-table pa-cmp-table"><caption class="sr-only">Each step of the path for identity A and identity B; the first step where they differ is marked</caption>
        <thead><tr><th scope="col">Step</th><th scope="col">A</th><th scope="col">B</th></tr></thead><tbody>${rows}</tbody></table></div>
      <p class="df-hint">Configuration predictions for the same destination, network and traffic. A is the what-if and device above; B is what you gave here.</p>
    </section>`;
    const exp = fmt => async () => {
      try {
        const r = await fetch(`/api/path-analyzer/compare/${encodeURIComponent(jobId)}/export?format=${fmt}`, { cache: 'no-store' });
        if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(errText(d, r.status)); }
        const blob = await r.blob();
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
        a.download = `path-compare-${String(res.destination || 'destination').replace(/[^a-z0-9.-]/gi, '_')}.${fmt}`;
        document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
        page.say(`Exported as ${fmt.toUpperCase()}.`);
      } catch (e) { page.say(`The export failed: ${e.message}`); }
    };
    document.getElementById('paCmpCsv').addEventListener('click', exp('csv'));
    document.getElementById('paCmpJson').addEventListener('click', exp('json'));
  }

  // ── Test from here ────────────────────────────────────────────────
  const PROBE_PORTS = [['', 'From the URL'], ['443', '443 (HTTPS)'], ['80', '80 (connect only)'], ['8443', '8443'], ['8080', '8080']];
  function probeSection(res) {
    const d = res.destination || {};
    return `<section class="pa-probe" id="paProbeSec" aria-labelledby="paProbeH">
      <h2 class="df-h" id="paProbeH">Test from here</h2>
      <p class="df-hint"><strong>From the computer running this app</strong> (in the Docker container, the container’s network), not from the user’s device: one DNS lookup, a TCP connect and, on a TLS port, a TLS handshake to ${E(d.host)}, then the certificate compared with the prediction above. It sends no HTTP request, no data and no credentials, follows no redirect, and only on ports 443, 80, 8443 and 8080. Nothing is kept.</p>
      <div class="pl-row"><label class="df-ctl"><span class="lbl">Port</span><select id="paProbePort" aria-label="Port to test from here">${PROBE_PORTS.map(([v, l]) => `<option value="${E(v)}">${E(l)}</option>`).join('')}</select></label>
        <button type="button" class="rp-btn primary" id="paProbeRun">Test from here</button></div>
      <div id="paProbeOut" aria-live="polite"></div>
    </section>`;
  }
  function prediction(res) {
    const v = res.verdict || {};
    const zpa = (res.modules || []).some(m => String(m.key || '').startsWith('zpa')) ? ['zpa_allowed', 'zpa_denied'].includes(v.outcome) : undefined;
    return { outcome: v.outcome, headline: v.headline, reaches_zscaler: typeof v.reaches_zscaler === 'boolean' ? v.reaches_zscaler : undefined,
      decrypted: typeof v.decrypted === 'boolean' ? v.decrypted : undefined, zpa, stops_at: v.stops_at || undefined };
  }
  let probing = false;
  async function probeRun(res) {
    if (probing) return;
    const out = document.getElementById('paProbeOut'), btn = document.getElementById('paProbeRun');
    probing = true; btn.disabled = true; btn.textContent = 'Testing…';
    out.innerHTML = '<p class="df-hint">Testing from this computer…</p>';
    try {
      const port = document.getElementById('paProbePort').value;
      const body = { destination: (res.destination || {}).input || page.destination(), prediction: prediction(res), confirm: true };
      if (port) body.port = port;
      const o = await post('/api/path-analyzer/test-from-here', body);
      out.innerHTML = probeHtml(o);
      page.say(`Tested from here: ${(o.comparison || []).map(c => `${c.topic} ${c.agrees === true ? 'agrees' : c.agrees === false ? 'differs' : 'cannot tell'}`).join('; ')}.`);
    } catch (e) {
      out.innerHTML = `<div class="bp-card risk"><div class="t">The test did not run</div><div>${E(e.message)}</div></div>`;
      page.say(`The test did not run: ${e.message}`);
    } finally { probing = false; btn.disabled = false; btn.textContent = 'Test from here'; }
  }
  function probeHtml(o) {
    const dns = o.dns || {}, tcp = o.tcp || {}, tls = o.tls || {}, c = tls.certificate || {};
    const yn = (b, y, n) => (b === true ? y : b === false ? n : 'unknown');
    const rows = [
      ['Name lookup', dns.ok ? `${(dns.addresses || []).join(', ')}${dns.zpa_synthetic ? ' (a ZPA synthetic address)' : ''}` : dns.ok === false ? `failed: ${dns.error}` : 'not done', dns.how],
      ['TCP connect', tcp.ok ? `connected to ${tcp.address}:${o.port} in ${tcp.ms} ms` : tcp.ok === false ? `failed: ${tcp.error}` : 'not done', ''],
      ['TLS handshake', !tls.attempted ? 'not on this port' : tls.ok ? `${tls.version || 'TLS'}, ${tls.cipher || ''}` : tls.ok === false ? `failed: ${tls.error}` : 'not done', ''],
      ['Certificate issuer', c.read ? `${c.issuer_cn || ''}${c.issuer_o ? ` (${c.issuer_o})` : ''}` : 'unknown', c.read ? (c.zscaler ? 'Zscaler’s name: an inspection certificate' : 'not Zscaler’s name') : ''],
      ['Certificate subject', c.read ? `${c.subject_cn || ''}${c.subject_o ? ` (${c.subject_o})` : ''}` : 'unknown', ''],
      ['Names on it', c.read ? ((c.sans || []).join(', ') + (c.sans_more ? ` and ${c.sans_more} more` : '')) || 'none' : 'unknown', ''],
      ['Trusted by this computer', tls.ok ? yn(tls.trusted, 'yes', `no${tls.trust_error ? ': ' + tls.trust_error : ''}`) : 'unknown', ''],
    ];
    const cmp = (o.comparison || []).map(x => `<li class="pa-probe-cmp ${x.agrees === true ? 'ok' : x.agrees === false ? 'no' : 'dim'}">
        <span class="df-chip st-${x.agrees === true ? 'ok' : x.agrees === false ? 'fail' : 'dim'}">${x.agrees === true ? 'Agrees' : x.agrees === false ? 'Differs' : 'Cannot tell'}</span>
        <strong>${E(x.topic)}</strong>: predicted ${E(x.predicted)}; observed ${E(x.observed)}.<div class="df-hop-d">${E(x.note)}</div></li>`).join('');
    return `<p class="df-hint"><strong>Observed ${E(o.where)}</strong>, ${E(new Date((o.at || Date.now() / 1000) * 1000).toLocaleString())}, port ${E(o.port)}. Sent: ${E(o.sent)}</p>
      <ul class="pa-probe-list">${cmp}</ul>
      <div class="df-tablewrap"><table class="df-table pa-probe-table"><caption class="sr-only">What this computer observed</caption>
        <thead><tr><th scope="col">Step</th><th scope="col">Observed</th><th scope="col">Note</th></tr></thead>
        <tbody>${rows.map(r => `<tr><th scope="row">${E(r[0])}</th><td>${E(r[1])}</td><td class="df-by">${E(r[2])}</td></tr>`).join('')}</tbody></table></div>`;
  }

  // ── Manual inputs (what-if) ───────────────────────────────────────
  const MAN_FIELDS = { paManPac: 'pac_text', paManVpn: 'vpn_gateways', paManIpInc: 'ipv4_include', paManIpExc: 'ipv4_exclude',
    paManDomInc: 'dest_include', paManDomExc: 'dest_exclude' };
  function manual() {
    const out = {};
    let any = false;
    Object.entries(MAN_FIELDS).forEach(([id, key]) => {
      const el = document.getElementById(id); const v = el ? String(el.value || '') : '';
      if (v.trim()) { out[key] = v; any = true; }
    });
    if (!any) return null;
    const merge = document.getElementById('paManMerge');
    out.mode = merge && merge.checked ? 'merge' : 'alone';
    return out;
  }
  function manualNote() {
    const el = document.getElementById('paManNote'); if (!el) return;
    const m = manual();
    el.textContent = !m ? '' : (m.mode === 'merge' && !zccInScope() ? 'Adding them to the tenant\'s app profiles needs ZCC ticked on the Scope page; on their own they need nothing read.'
      : 'The next analysis includes these inputs as a what-if.');
  }
  function manualSection(mi) {
    if (!mi) return '';
    const g = mi.given || {}, by = mi.decided_by;
    const given = [['PAC', g.pac_chars ? `${g.pac_chars} characters` : ''], ['VPN gateways', g.vpn_gateways], ['IP inclusions', g.ipv4_include], ['IP exclusions', g.ipv4_exclude],
      ['Domain inclusions', g.dest_include], ['Domain exclusions', g.dest_exclude]].filter(x => x[1]).map(x => `${x[0]}: ${x[1]}`).join(' · ');
    const pac = mi.pac ? `<p class="df-hop-d"><strong>Pasted PAC:</strong> ${E(word(mi.pac.status))}. ${E(mi.pac.detail)}</p>` : '';
    const merged = mi.merged ? `<p class="df-hop-d">Added to ${E(mi.merged.profiles)} app profile(s) read; the whole trace above is a what-if.</p>` : (mi.merged_note ? `<p class="df-hop-d">${E(mi.merged_note)}</p>` : '');
    return `<section class="pa-device-out" id="paManualOut" aria-labelledby="paManOutH">
      <h2 class="df-h" id="paManOutH">${E(mi.label || 'Manual inputs (what-if)')}: ${E(word(mi.outcome))}</h2>
      <p class="df-hop-d"><strong>${E(mi.headline)}</strong>${by ? ` Decided by ${E(by.list)}: ${E(by.entry)}.` : ''}</p>
      ${pac}${merged}
      ${(mi.notes || []).length ? `<ul class="pa-assume">${mi.notes.map(n => `<li>${E(n)}</li>`).join('')}</ul>` : ''}
      <p class="df-hint">${E(mi.note)}${given ? ` Given: ${E(given)}.` : ''}</p>
    </section>`;
  }

  // ── Wiring ─────────────────────────────────────────────────────────
  function init(fns) {
    page = Object.assign(page, fns || {});
    devA.init(); devB.init();
    ['paDevice', 'paCompare'].forEach(id => { const d = document.getElementById(id); if (d) d.addEventListener('toggle', () => { devA.refresh(); devB.refresh(); }); });
    const run = document.getElementById('paCmpRun'); if (run) run.addEventListener('click', compareRun);
    Object.keys(MAN_FIELDS).concat(['paManAlone', 'paManMerge']).forEach(id => { const el = document.getElementById(id); if (el) el.addEventListener(el.type === 'radio' ? 'change' : 'input', manualNote); });
    const clr = document.getElementById('paManClear');
    if (clr) clr.addEventListener('click', () => {
      Object.keys(MAN_FIELDS).forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
      const a = document.getElementById('paManAlone'); if (a) a.checked = true;
      manualNote(); page.say('Manual inputs cleared.');
    });
  }
  // After a result is drawn: the device block and Test from here, after the
  // live path (which stays right under the verdict).
  function afterRender(res, body) {
    const anchor = body.querySelector('#paFlowSec') || body.querySelector('.pa-verdict');
    const html = manualSection(res.manual_inputs) + deviceSection(res.device) + (res.destination ? probeSection(res) : '');
    if (anchor) anchor.insertAdjacentHTML('afterend', html); else body.insertAdjacentHTML('afterbegin', html);
    const b = document.getElementById('paProbeRun'); if (b) b.addEventListener('click', () => probeRun(res));
  }

  window.PathExtras = { init, afterRender, device: () => devA.value(), manual, _word: word, _probeHtml: probeHtml, _deviceSection: deviceSection, _manualSection: manualSection };
})();
