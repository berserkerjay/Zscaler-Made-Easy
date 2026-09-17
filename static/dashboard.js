// ── Dashboard layout add-on ──────────────────────────────────────────
// Turns the assessment page into the dashboard look: a left sidebar
// (workflow steps, then every tool the toolbar had, grouped the same
// way; the current tenant; the theme toggle), a compact header, and the
// results drawn as an Overall Maturity Score ring with the maturity band,
// a Completion ring, a Score Distribution radar, one pillar card per
// section, Key Insights and action tiles, with the findings as list rows
// carrying a risk chip and a sticky progress footer.
//
// Nothing here is a new source of truth: the sidebar MOVES the toolbar's
// own buttons (same onclick, same labels), the dashboard reads the same
// results object showResults() receives, and every id the inline script
// updates (#scoreNum, #scoreLabel, #scoreMeta, #passCount…) stays where
// the inline script expects it. Loads last, so it can wrap showResults.
(function () {
  if (window.__dbReady || (location.pathname.replace(/\/+$/, '') || '/') !== '/') return;
  const container = document.querySelector('.container');
  const toolbar = document.querySelector('.hero-toolbar');
  const hero = document.querySelector('.hero');
  if (!container || !toolbar || !hero) return;
  window.__dbReady = true;
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const $ = id => document.getElementById(id);

  // ── 1. Sidebar ──────────────────────────────────────────────────
  document.body.classList.add('db-layout');
  const aside = document.createElement('aside');
  aside.id = 'dbSidebar';
  aside.setAttribute('aria-label', 'Navigation');
  aside.innerHTML = `
    <div class="db-brand"><span class="db-mark" aria-hidden="true">Z</span><div><div class="db-brand-t">Zscaler Assessment</div><div class="db-brand-s">DLP-Check</div></div></div>
    <nav class="db-nav" aria-label="Workflow">
      <div class="db-nav-l">Workflow</div>
      <button type="button" class="db-item" data-db="dashboard" aria-current="page"><span class="db-ico" aria-hidden="true">📊</span>Dashboard</button>
      <button type="button" class="db-item" data-db="configure"><span class="db-ico" aria-hidden="true">🔐</span>Connect to the tenant</button>
      <button type="button" class="db-item" data-db="scope"><span class="db-ico" aria-hidden="true">🎯</span>Scope</button>
      <button type="button" class="db-item" data-db="run"><span class="db-ico" aria-hidden="true">▶</span><span class="db-lbl">Run assessment</span></button>
      <button type="button" class="db-item" data-db="review"><span class="db-ico" aria-hidden="true">📋</span>Findings &amp; report</button>
    </nav>
    <div id="dbTools" role="navigation" aria-label="Tools"></div>
    <div class="db-current" id="dbCurrent" aria-label="Current implementation">
      <div class="db-current-l">Current implementation</div>
      <div class="db-current-row"><span class="k">Tenant</span><span class="v" id="dbCurTenant">—</span></div>
      <div class="db-current-row"><span class="k">Last score</span><span class="v" id="dbCurScore">—</span></div>
      <div class="db-current-row"><span class="k">Saved</span><span class="v" id="dbCurSaved">Never</span></div>
    </div>
    <div class="db-foot" id="dbFoot"><span id="dbBuild"></span></div>`;
  document.body.insertBefore(aside, container);
  const tools = $('dbTools');
  [...toolbar.querySelectorAll('.tool-group')].forEach(g => tools.appendChild(g));
  toolbar.hidden = true;
  // The theme toggle (rendered by the inline script) and the backdrop
  // control (rendered only with branding files) live in the sidebar foot.
  const dock = () => {
    const foot = $('dbFoot');
    ['themeToggleBtn', 'bgIntensityControl'].forEach(id => { const el = $(id); if (el && el.parentElement !== foot) foot.appendChild(el); });
  };
  dock(); setTimeout(dock, 800); setTimeout(dock, 3000);
  // ☰ on narrow screens
  const menu = document.createElement('button');
  menu.id = 'dbMenuBtn'; menu.type = 'button'; menu.setAttribute('aria-controls', 'dbSidebar'); menu.setAttribute('aria-expanded', 'false'); menu.textContent = '☰ Menu';
  menu.addEventListener('click', () => { const open = !document.body.classList.contains('db-open'); document.body.classList.toggle('db-open', open); menu.setAttribute('aria-expanded', String(open)); });
  document.body.insertBefore(menu, aside);
  // ── Run assessment from the sidebar ─────────────────────────────
  // Sign in first when needed, then run on this page and land on the
  // dashboard (no pop-out tab): missing details → the Connect step opens
  // on the first blank field and the run is queued; not yet authenticated
  // → Authenticate runs, then the assessment; already signed in → run.
  const say = t => { if (typeof announce === 'function') announce(t); };
  const FIELD_LABELS = { org: 'Organization Name', assessor: 'Assessor Name', vd: 'Vanity Domain', cid: 'Client ID', csec: 'Client Secret', zuser: 'Admin Username', zpass: 'Admin Password', zkey: 'API Key' };
  function missingFields() {
    const v = id => (($(id) || {}).value || '').trim();
    const legacy = typeof currentAuthMethod === 'function' && currentAuthMethod() === 'legacy';
    const remembered = typeof profileHasSecret === 'function' && profileHasSecret();
    const need = ['org', 'assessor'].concat(legacy ? ['zuser', 'zpass', 'zkey'] : ['vd', 'cid', 'csec']);
    return need.filter(id => !v(id) && !(remembered && (id === 'csec' || id === 'zpass' || id === 'zkey')));
  }
  function signedIn() {
    const c = window.GD && GD.conn;
    if (!c || !c.ok) return false;
    const legacy = typeof currentAuthMethod === 'function' && currentAuthMethod() === 'legacy';
    const ident = (($(legacy ? 'zuser' : 'vd') || {}).value || '').trim();
    return !c.vd || c.vd === ident;
  }
  function note(text, kind) {
    let n = $('dbRunNote');
    if (!n) { n = document.createElement('div'); n.id = 'dbRunNote'; n.className = 'db-note'; n.setAttribute('role', 'status'); const run = aside.querySelector('.db-item[data-db="run"]'); run.insertAdjacentElement('afterend', n); }
    n.textContent = text || ''; n.hidden = !text; n.className = 'db-note' + (kind ? ' ' + kind : '');
  }
  let pendingRun = false;
  function goConnect(first) {
    if (typeof _gdGoConfig === 'function') _gdGoConfig(); else if (typeof _stepGo === 'function') _stepGo('configure');
    setCurrent('configure');
    if (first) setTimeout(() => { const el = $(first); if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); el.focus(); } }, 450);
  }
  function startRun() {
    pendingRun = false; note('');
    if (typeof runAssessment !== 'function') return;
    const btn = $('runBtn');
    if (btn && btn.disabled) return;   // already running (the Authenticate wrapper started it)
    runAssessment();
    if (btn && btn.disabled) { setCurrent('run'); const prog = $('progressCard'); if (prog) prog.scrollIntoView({ behavior: 'smooth', block: 'start' }); say('Assessment started. The results open on this page when it finishes.'); }
  }
  async function runFromSidebar() {
    const btn = $('runBtn');
    if (btn && btn.disabled) { say('The assessment is already running.'); return; }
    const missing = missingFields();
    if (missing.length) {
      pendingRun = true;
      note(`Sign in first: fill in ${missing.map(id => FIELD_LABELS[id] || id).join(', ')} and click Authenticate. The assessment starts by itself right after.`, 'warn');
      say('Sign in first. Fill in the tenant details and click Authenticate; the assessment starts right after.');
      goConnect(missing[0]);
      return;
    }
    if (!signedIn()) {
      pendingRun = true;
      note('Authenticating with the tenant, then running the assessment…');
      setCurrent('configure');
      if (typeof authenticateTenant === 'function') await authenticateTenant();
      if (!pendingRun) return;          // the Authenticate wrapper already started the run
      if (signedIn()) { startRun(); return; }
      note('The tenant did not accept the sign-in. Fix the details in Connect to the tenant and click Authenticate; the assessment starts right after.', 'warn');
      goConnect();
      return;
    }
    startRun();
  }
  // A successful Authenticate (the guide's button or the form's) starts a queued run.
  const origTest = window._gdTest;
  if (typeof origTest === 'function') window._gdTest = async function () { const r = await origTest.apply(this, arguments); if (pendingRun && signedIn()) startRun(); return r; };
  // Workflow items: the same routes as the step strip, except Run.
  aside.querySelectorAll('.db-item').forEach(b => b.addEventListener('click', () => {
    const k = b.dataset.db;
    document.body.classList.remove('db-open'); menu.setAttribute('aria-expanded', 'false');
    if (k === 'dashboard') { const r = $('results'); if (r && getComputedStyle(r).display !== 'none') r.scrollIntoView({ behavior: 'smooth', block: 'start' }); else window.scrollTo({ top: 0, behavior: 'smooth' }); setCurrent('dashboard'); return; }
    if (k === 'run') { runFromSidebar(); return; }
    if (typeof _stepGo === 'function') _stepGo(k);
    setCurrent(k);
  }));
  window.__dbRunFromSidebar = runFromSidebar;
  function setCurrent(k) { aside.querySelectorAll('.db-item').forEach(b => { if (b.dataset.db === k) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); }); }
  // Follow the step strip when the inline script moves it.
  const strip = $('stepBar');
  if (strip && window.MutationObserver) new MutationObserver(() => { const cur = strip.querySelector('.step-item[aria-current="step"]'); if (cur) setCurrent(cur.dataset.step); }).observe(strip, { subtree: true, attributes: true, attributeFilter: ['aria-current'] });

  // Current implementation: tenant from the form / profile, build from /api/health.
  function refreshCurrent() {
    const vd = ($('vd') || {}).value || '';
    const cloud = ($('cloud') || {}).value || '';
    const prof = (window.GD && GD.profile) ? GD.profile : '';
    const t = $('dbCurTenant'); if (t) { t.textContent = vd ? `${vd}${cloud ? ' · ' + cloud : ''}` : (prof ? `profile ${prof}` : 'not connected'); t.title = t.textContent; }
    const s = $('dbCurSaved'); if (s) s.textContent = prof ? 'Profile selected' : 'Never';
    const run = aside.querySelector('.db-item[data-db="run"]'), btn = $('runBtn');
    if (run && btn) { const busy = !!btn.disabled; run.classList.toggle('busy', busy); run.setAttribute('aria-busy', String(busy)); run.querySelector('.db-ico').textContent = busy ? '⏳' : '▶'; run.querySelector('.db-lbl').textContent = busy ? 'Running…' : 'Run assessment'; }
  }
  refreshCurrent(); setInterval(refreshCurrent, 2500);
  fetch('/api/health', { cache: 'no-store' }).then(r => r.ok ? r.json() : null).then(d => { const b = $('dbBuild'); if (b && d) b.textContent = `Build ${String(d.commit || d.version || '').slice(0, 7) || '—'}`; }).catch(() => {});

  // ── 2. Dashboard hero (built once; ids the inline script sets stay) ─
  // .db-dash / .db-rows travel with the results HTML into the mirrored
  // results tab (report_view.html links dashboard.css), so the rings and
  // rows are styled there too.
  const heroCard = document.querySelector('.score-hero');
  const checksList = $('checksList');
  if (checksList) checksList.classList.add('db-rows');
  if (heroCard) {
    heroCard.classList.add('db-dash');
    heroCard.innerHTML = `
      <div class="db-grid">
        <div class="db-tile glow">
          <div class="db-tile-t">Overall Maturity Score</div>
          <div class="db-ring">
            <svg viewBox="0 0 120 120" role="img" aria-labelledby="dbRingLbl"><title id="dbRingLbl">Overall maturity score</title>
              <defs><linearGradient id="dbRingGrad" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3b82f6"/><stop offset="0.6" stop-color="#22d3ee"/><stop offset="1" stop-color="#a78bfa"/></linearGradient></defs>
              <circle class="track" cx="60" cy="60" r="50"/><circle class="arc" id="dbRingArc" cx="60" cy="60" r="50" stroke-dasharray="314.16" stroke-dashoffset="314.16"/>
            </svg>
            <div class="db-ring-txt">
              <div class="score-num" id="scoreNum">0%</div>
              <div class="score-label" id="scoreLabel">Maturity Level</div>
              <div class="score-meta" id="scoreMeta"></div>
            </div>
          </div>
          <div class="db-band" id="dbBand" aria-label="Maturity band"></div>
        </div>
        <div class="db-tile">
          <div class="db-tile-t">Completion</div>
          <div class="db-ring small">
            <svg viewBox="0 0 120 120" role="img" aria-labelledby="dbCompLbl"><title id="dbCompLbl">Assessment completion</title>
              <circle class="track" cx="60" cy="60" r="50"/><circle class="arc" id="dbCompArc" cx="60" cy="60" r="50" stroke-dasharray="314.16" stroke-dashoffset="314.16"/>
            </svg>
            <div class="db-ring-txt"><div class="db-comp-n" id="dbCompPct">0%</div><div class="db-comp-s" id="dbCompTxt">no checks yet</div></div>
          </div>
        </div>
        <div class="db-tile db-radar">
          <div class="db-tile-t">Score Distribution</div>
          <div id="dbRadar"></div>
        </div>
      </div>
      <div class="db-pillars" id="dbPillars"></div>
      <div class="db-two">
        <div class="db-tile"><div class="db-tile-t">Key Insights</div><ul class="db-insights" id="dbInsights"></ul></div>
        <div class="db-tile"><div class="db-tile-t">Next actions</div><div class="db-actions" id="dbActions"></div></div>
      </div>`;
  }
  const BAND = ['Ad Hoc', 'Initial', 'Developing', 'Managed', 'Optimized'];   // dlp_assessment_full_auto.maturity(): <25, <50, <75, <90, 90+
  const pctColor = p => p >= 75 ? 'var(--pass)' : p >= 50 ? 'var(--warn)' : 'var(--fail)';
  const level = p => p >= 90 ? ['Optimized', 'ok'] : p >= 75 ? ['Managed', 'ok'] : p >= 50 ? ['Developing', 'warn'] : p >= 25 ? ['Initial', 'fail'] : ['Ad Hoc', 'fail'];
  function ring(id, pct) { const a = $(id); if (!a) return; const C = 2 * Math.PI * 50; a.style.strokeDashoffset = String(C * (1 - Math.max(0, Math.min(100, pct || 0)) / 100)); }
  function radar(sections) {
    const host = $('dbRadar'); if (!host) return;
    const names = Object.keys(sections || {});
    if (names.length < 3) { host.innerHTML = `<div class="db-comp-s">${names.length ? 'Three or more sections are needed for the radar; the pillar cards below carry the scores.' : 'No sections scored yet.'}</div>`; return; }
    const n = names.length, cx = 110, cy = 95, R = 68;
    const pt = (i, r) => { const a = -Math.PI / 2 + (2 * Math.PI * i) / n; return [cx + r * Math.cos(a), cy + r * Math.sin(a)]; };
    const web = [0.25, 0.5, 0.75, 1].map(f => `<polygon class="web" points="${names.map((_, i) => pt(i, R * f).map(v => v.toFixed(1)).join(',')).join(' ')}"/>`).join('');
    const spokes = names.map((_, i) => { const [x, y] = pt(i, R); return `<line class="web" x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}"/>`; }).join('');
    const pts = names.map((k, i) => pt(i, R * Math.max(0, Math.min(100, sections[k].pct || 0)) / 100));
    const labels = names.map((k, i) => { const [x, y] = pt(i, R + 14); const short = k.replace(/^[\d.]+\s*[—-]\s*/, '').replace(/^Ch\.\w+\s*[—-]\s*/, ''); return `<text x="${x.toFixed(1)}" y="${y.toFixed(1)}" text-anchor="${x < cx - 4 ? 'end' : x > cx + 4 ? 'start' : 'middle'}" dominant-baseline="middle">${E(short.slice(0, 18))}</text>`; }).join('');
    host.innerHTML = `<svg viewBox="0 0 220 190" role="img" aria-label="Score by section: ${E(names.map(k => `${k} ${sections[k].pct}%`).join(', '))}">${web}${spokes}<polygon class="area" points="${pts.map(p => p.map(v => v.toFixed(1)).join(',')).join(' ')}"/>${pts.map(p => `<circle class="pt" cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="2.5"/>`).join('')}${labels}</svg>`;
  }
  const ICONS = [[/ssl|tls/i, '🔒'], [/firewall|fw/i, '🧱'], [/dlp|data|inline|web/i, '🛡️'], [/incident|workflow/i, '🚨'], [/genai|ai\b/i, '🤖'], [/zpa|access/i, '🔑'], [/zcc|client|portal/i, '💻'], [/compliance|regulat/i, '📜'], [/email|mail/i, '✉️'], [/saas|cloud/i, '☁️'], [/endpoint|device/i, '🖥️'], [/log|nss|siem/i, '🧾']];
  const icon = name => (ICONS.find(([re]) => re.test(name || '')) || [null, '📁'])[1];
  function pillars(sections) {
    const host = $('dbPillars'); if (!host) return;
    host.innerHTML = Object.entries(sections || {}).map(([name, d]) => {
      const [lv, cls] = level(d.pct || 0);
      const scored = (d.total || 0) - (d.info || 0);
      return `<button type="button" class="db-pillar" data-section="${E(name)}" aria-label="${E(name)}: ${d.pct}%, ${d.pass || 0} of ${scored} configured, ${lv}. Show these findings.">
        <div class="db-pillar-h"><span class="db-pillar-n"><span aria-hidden="true">${icon(name)}</span> ${E(name)}</span><span class="db-pillar-p" style="color:${pctColor(d.pct || 0)}">${d.pct}%</span></div>
        <div class="db-bar"><i style="width:${Math.max(0, Math.min(100, d.pct || 0))}%"></i></div>
        <div class="db-pillar-m"><span>${d.pass || 0}/${scored} configured${d.fail ? ` · ${d.fail} to fix` : ''}${d.warn ? ` · ${d.warn} to review` : ''}</span><span class="db-chip ${cls}">${lv}</span></div>
      </button>`;
    }).join('');
    host.querySelectorAll('.db-pillar').forEach(b => b.addEventListener('click', () => {
      const name = b.dataset.section;
      const hdr = [...document.querySelectorAll('#checksList .section-header')].find(h => h.textContent.trim() === name);
      if (hdr) { hdr.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
    }));
  }
  function insights(data) {
    const host = $('dbInsights'); if (!host) return;
    const checks = data.checks || [];
    const fails = checks.filter(c => c.status === 'FAIL'), reviews = checks.filter(c => c.status === 'REVIEW'), passes = checks.filter(c => c.status === 'PASS');
    const secs = Object.entries(data.sections || {});
    const weakest = secs.slice().sort((a, b) => (a[1].pct || 0) - (b[1].pct || 0))[0];
    const strongest = secs.slice().sort((a, b) => (b[1].pct || 0) - (a[1].pct || 0))[0];
    const items = [];
    if (fails.length) items.push(['fail', '⚠️', `<strong>${fails.length} finding${fails.length === 1 ? '' : 's'} need action.</strong> First: ${E(fails[0].label)}${fails[0].plain && fails[0].plain.means ? ` — ${E(fails[0].plain.means)}` : ''}`]);
    if (weakest && weakest[1].pct < 75) items.push(['warn', '📉', `<strong>Weakest area: ${E(weakest[0])}</strong> at ${weakest[1].pct}% (${weakest[1].fail || 0} to fix, ${weakest[1].warn || 0} to review).`]);
    if (reviews.length) items.push(['warn', '🔎', `<strong>${reviews.length} item${reviews.length === 1 ? '' : 's'} to review</strong> with the customer: they are configured, but not the way Zscaler recommends.`]);
    if (strongest && strongest[1].pct >= 75) items.push(['ok', '✅', `<strong>Strongest area: ${E(strongest[0])}</strong> at ${strongest[1].pct}%; ${strongest[1].pass || 0} checks configured.`]);
    if (data.permissions && data.permissions.blocked) items.push(['warn', '🔏', `<strong>${data.permissions.blocked} check${data.permissions.blocked === 1 ? '' : 's'} could not run</strong>: the API client's role lacks their feature. The card below says what to grant.`]);
    if (!items.length) items.push(['ok', '✅', `<strong>${passes.length} of ${checks.length} checks configured.</strong> Nothing needs action.`]);
    host.innerHTML = items.slice(0, 5).map(([cls, ico, html]) => `<li class="${cls}"><span class="db-ico" aria-hidden="true">${ico}</span><span>${html}</span></li>`).join('');
  }
  function actions(data) {
    const host = $('dbActions'); if (!host) return;
    const fails = (data.checks || []).filter(c => c.status === 'FAIL').length;
    const A = [
      ['🔧', 'Review & Remediate', fails ? `${fails} finding${fails === 1 ? '' : 's'} to fix` : 'nothing to fix', () => typeof openRemediationReview === 'function' && openRemediationReview()],
      ['🗺️', 'Traffic Flow & Gaps', 'where inspection is lost', () => typeof openDataFlowTab === 'function' && openDataFlowTab()],
      ['📄', 'Generate report', 'Word document for the customer', () => typeof downloadDocx === 'function' && downloadDocx()],
      ['📦', 'Deploy a policy pack', 'close the gaps, preflight first', () => typeof openDlpPacksModal === 'function' && openDlpPacksModal()],
      ['🧭', 'Path Analyzer', 'what blocks one destination', () => typeof openPathAnalyzerTab === 'function' && openPathAnalyzerTab()],
      ['🔁', 'Run another assessment', 'after the fixes', () => typeof resetForm === 'function' && resetForm()],
    ];
    host.innerHTML = A.map(([ico, t, s], i) => `<button type="button" class="db-action" data-i="${i}"><span class="db-ico" aria-hidden="true">${ico}</span><strong>${E(t)}</strong><span class="s">${E(s)}</span></button>`).join('');
    host.querySelectorAll('.db-action').forEach(b => b.addEventListener('click', () => A[Number(b.dataset.i)][3]()));
  }
  function band(score) {
    const host = $('dbBand'); if (!host) return;
    const idx = score >= 90 ? 4 : score >= 75 ? 3 : score >= 50 ? 2 : score >= 25 ? 1 : 0;
    host.innerHTML = BAND.map((b, i) => `<span class="${i < idx ? 'done' : i === idx ? 'now' : ''}" ${i === idx ? 'aria-current="true"' : ''}>${b}</span>`).join('');
  }
  function footer(data) {
    let f = $('dbFooter');
    if (!f) { f = document.createElement('div'); f.id = 'dbFooter'; f.setAttribute('role', 'status'); f.setAttribute('aria-live', 'polite'); document.body.appendChild(f); }
    const checks = data.checks || [];
    const ok = checks.filter(c => c.status === 'PASS').length, gaps = checks.filter(c => c.status === 'FAIL').length, rev = checks.filter(c => c.status === 'REVIEW').length;
    f.innerHTML = `<span><strong>${ok} of ${checks.length}</strong> checks configured · <strong>${gaps}</strong> gap${gaps === 1 ? '' : 's'} remaining${rev ? ` · ${rev} to review` : ''}</span>
      <button type="button" class="db-foot-btn" id="dbFootBtn">${gaps ? 'Continue to Review & Remediate →' : 'Generate the report →'}</button>`;
    $('dbFootBtn').addEventListener('click', () => { if (gaps && typeof openRemediationReview === 'function') openRemediationReview(); else if (typeof downloadDocx === 'function') downloadDocx(); });
    f.hidden = false;
    document.body.classList.add('db-has-footer');
  }
  function decorateChecks() {
    document.querySelectorAll('#checksList .check-item').forEach(row => {
      if (row.dataset.ico) return;
      const hdr = row.previousElementSibling && row.previousElementSibling.classList.contains('section-header') ? row.previousElementSibling : (() => { let p = row.previousElementSibling; while (p && !p.classList.contains('section-header')) p = p.previousElementSibling; return p; })();
      const sec = hdr ? hdr.textContent.trim() : '';
      row.dataset.ico = icon(sec);
      const st = row.querySelector('.check-status');
      if (st) { const risk = { 'Action Required': ['High Risk', 'status-FAIL'], 'Needs Review': ['Medium Risk', 'status-REVIEW'], 'Not Configured': ['Low Risk', 'status-INFO'], 'Configured': ['Configured', 'status-PASS'] }[st.textContent.trim()]; if (risk) st.title = `${st.textContent.trim()} · ${risk[0]}`; }
      const label = row.querySelector('.check-label');
      if (label && sec && !row.querySelector('.db-cat')) label.insertAdjacentHTML('afterend', `<span class="db-cat">${E(sec)}</span>`);
    });
  }
  function renderDashboard(data) {
    const score = Number(data.score) || 0;
    ring('dbRingArc', score); band(score);
    const checks = data.checks || [], blocked = (data.permissions && data.permissions.blocked) || 0;
    const ran = Math.max(0, checks.length - blocked), comp = checks.length ? Math.round(ran / checks.length * 100) : 0;
    ring('dbCompArc', comp);
    const cp = $('dbCompPct'), ct = $('dbCompTxt');
    if (cp) cp.textContent = `${comp}%`;
    if (ct) ct.textContent = blocked ? `${ran} of ${checks.length} checks ran; ${blocked} not permitted` : `${checks.length} checks ran`;
    radar(data.sections); pillars(data.sections); insights(data); actions(data); footer(data); decorateChecks();
    const s = $('dbCurScore'); if (s) s.textContent = `${score}% · ${data.maturity || level(score)[0]}`;
    setCurrent('dashboard');
  }
  // Wrap the inline script's entry points (top-level function declarations are window properties).
  const origShow = window.showResults, origRender = window.renderChecks, origReset = window.resetForm;
  if (typeof origShow === 'function') window.showResults = function (data) { origShow.apply(this, arguments); try { renderDashboard(data || {}); } catch (e) { console.error('dashboard', e); } };
  if (typeof origRender === 'function') window.renderChecks = function () { origRender.apply(this, arguments); try { decorateChecks(); } catch (e) { /* cosmetic */ } };
  if (typeof origReset === 'function') window.resetForm = function () { origReset.apply(this, arguments); const f = $('dbFooter'); if (f) f.hidden = true; document.body.classList.remove('db-has-footer'); setCurrent('configure'); };
  window.__dbRender = renderDashboard;
})();
