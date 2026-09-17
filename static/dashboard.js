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

  // ── Tenant configuration: the "Start here" guide with the tenant
  // details form is a sign-in surface, not part of the dashboard. Hidden
  // by default; revealed only by going to Connect to the tenant, from
  // this sidebar or the legacy step strip above it, or whenever the app
  // itself sends the operator there (a missing field, a failed sign-in,
  // a reset). Scope has its own combined page (Channels, Assessment
  // Scope, Compliance Frameworks) — see below.
  const CONFIG_VIEW_KEYS = new Set(['configure']);
  function showTenantConfig() { const gp = $('gdPanel'); if (gp) gp.hidden = false; const cc = $('configCard'); if (cc) cc.hidden = false; }
  function hideTenantConfig() { const gp = $('gdPanel'); if (gp) gp.hidden = true; const cc = $('configCard'); if (cc) cc.hidden = true; }
  hideTenantConfig();
  const origGoConfig = window._gdGoConfig;
  if (typeof origGoConfig === 'function') window._gdGoConfig = function () { showTenantConfig(); return origGoConfig.apply(this, arguments); };

  // Workflow items: the same routes as the step strip, except Run.
  aside.querySelectorAll('.db-item').forEach(b => b.addEventListener('click', () => {
    const k = b.dataset.db;
    document.body.classList.remove('db-open'); menu.setAttribute('aria-expanded', 'false');
    if (k === 'scope') { showScopeView(); setCurrent('scope'); return; }
    hideScopeView();
    if (k === 'dashboard') { const r = $('results'); if (r && getComputedStyle(r).display !== 'none') r.scrollIntoView({ behavior: 'smooth', block: 'start' }); else window.scrollTo({ top: 0, behavior: 'smooth' }); setCurrent('dashboard'); return; }
    if (k === 'run') { runFromSidebar(); return; }
    if (typeof _stepGo === 'function') _stepGo(k);
    setCurrent(k);
  }));
  window.__dbRunFromSidebar = runFromSidebar;

  // ── Scope: one combined page for everything that decides what the
  // assessment covers — which Zscaler data-security channels the
  // customer already owns (versus an alternative, versus a gap), which
  // parts of the platform to check, and which compliance frameworks the
  // report should map to. Channel ownership is a one-time input (there
  // is no API for "what does the customer already own"), kept in this
  // browser; Assessment Scope and Compliance Frameworks are the same
  // live form fields the assessment itself reads — moved here, not
  // copied, so nothing gets out of sync. ──────────────────────────────
  const CHANNELS_KEY = 'zassess_channels_v1';
  const CHANNELS = [
    { id: 'web_dlp', name: 'Inline Web DLP', risk: 'high', category: 'DLP', icon: '🌐',
      what: 'Data loss prevention for web traffic including HTTP/HTTPS (ports 80/443) and FTP. Inspects uploads, downloads, and web form submissions in real-time.' },
    { id: 'endpoint_dlp', name: 'Endpoint DLP', risk: 'high', category: 'DLP', icon: '💻',
      what: 'Data loss prevention at the endpoint level, controlling data movement on Windows and macOS devices including USB, printing, and local file operations.' },
    { id: 'email_dlp', name: 'Email DLP', risk: 'high', category: 'DLP', icon: '✉️',
      what: 'Data loss prevention for email communications, scanning outbound emails and attachments for sensitive content before delivery.' },
    { id: 'saas_casb', name: 'SaaS Security (CASB)', risk: 'high', category: 'Cloud Security', icon: '☁️',
      what: 'Cloud Access Security Broker providing visibility and control over SaaS application usage, data sharing, and security posture.' },
    { id: 'genai_security', name: 'GenAI Security', risk: 'high', category: 'AI Security', icon: '🤖',
      what: 'Controls and monitors usage of generative AI applications like ChatGPT, Copilot, and other AI tools to prevent data leakage and ensure responsible use.' },
    { id: 'shadow_it', name: 'Shadow IT Discovery', risk: 'medium', category: 'Visibility', icon: '🔍',
      what: 'Discovers and catalogs all cloud applications in use across the organization, identifying unsanctioned apps and risky behaviors.' },
    { id: 'endpoint_scan', name: 'Endpoint Data Scan', risk: 'medium', category: 'Data Discovery', icon: '💾',
      what: 'Scans endpoint file systems to discover and classify sensitive data at rest on Windows and macOS devices.' },
    { id: 'ssl_inspection', name: 'SSL/TLS Inspection', risk: 'critical', category: 'Infrastructure', icon: '🔒',
      what: 'Decrypts and inspects HTTPS traffic to enable visibility into encrypted communications for security and compliance purposes.' },
    { id: 'cloud_app_control', name: 'Cloud App Control', risk: 'medium', category: 'Access Control', icon: '🛡️',
      what: 'Granular controls for cloud applications including blocking, read-only access, and tenant restrictions.' },
    { id: 'device_control', name: 'Device Control', risk: 'medium', category: 'Endpoint Security', icon: '🔌',
      what: 'Controls access to removable media devices including USB drives, external hard drives, and other peripheral storage.' },
    { id: 'workflow_automation', name: 'Workflow Automation', risk: 'low', category: 'Operations', icon: '🔀',
      what: 'Automated incident response and remediation workflows for DLP events, reducing manual effort and response time.' },
  ];
  const RISK_LABEL = { critical: 'Critical Risk', high: 'High Risk', medium: 'Medium Risk', low: 'Low Risk' };
  const RISK_CLS = { critical: 'fail', high: 'warn-strong', medium: 'warn', low: 'ok' };
  function loadChannelState() {
    try { const raw = localStorage.getItem(CHANNELS_KEY); const d = raw ? JSON.parse(raw) : {}; return (d && typeof d === 'object') ? d : {}; } catch (e) { return {}; }
  }
  function saveChannelState(state) { try { localStorage.setItem(CHANNELS_KEY, JSON.stringify(state)); } catch (e) { /* private mode: the session still works, just doesn't persist */ } }
  let channelState = loadChannelState();     // { [id]: { choice: 'zscaler'|'alternative', note: '' } }
  let scopeView = null, channelsExtra = [];   // custom channels added with "+ Add Channel"
  try { channelsExtra = JSON.parse(localStorage.getItem(CHANNELS_KEY + '_extra') || '[]'); } catch (e) { channelsExtra = []; }
  function allChannels() { return CHANNELS.concat(channelsExtra); }
  function saveExtra() { try { localStorage.setItem(CHANNELS_KEY + '_extra', JSON.stringify(channelsExtra)); } catch (e) { /* ignore */ } }

  function buildScopeView() {
    const sec = document.createElement('section');
    sec.id = 'dbScopeView'; sec.hidden = true; sec.setAttribute('aria-label', 'Scope');
    sec.innerHTML = `
      <div class="hero db-ch-hero"><h1><span aria-hidden="true">🎯</span> Scope</h1>
        <p>What this assessment covers: the Zscaler data-security channels you already run, which parts of the platform to check, and which compliance frameworks the report should map to.</p></div>
      <div class="card db-scope-section" id="dbScopeChannelsCard">
        <div class="db-scope-section-h">
          <h2>Channels <span class="db-scope-tally" id="dbChFootTxt"></span></h2>
          <div class="db-ch-bar">
            <label class="df-ctl"><input type="checkbox" id="dbChSelectAll"> <span class="lbl">Select all</span></label>
            <span class="sep"></span>
            <button type="button" class="rp-btn primary" id="dbChAdd">+ Add channel</button>
          </div>
        </div>
        <p class="db-scope-p">Which Zscaler data security channels your organization owns. For channels you don't own, indicate if you use an alternative solution.</p>
        <div id="dbChList" class="db-ch-list"></div>
      </div>
      <div class="card db-scope-section" id="dbScopeAssessCard"><div id="dbScopeAssessBody"></div></div>
      <div class="card db-scope-section" id="dbScopeFwCard"><div id="dbScopeFwBody"></div></div>
      <div class="db-scope-foot">
        <button type="button" class="rp-btn primary" id="dbScopeContinue">Continue to Connect the tenant →</button>
      </div>`;
    const main = document.getElementById('main-content');
    main.insertBefore(sec, main.firstChild);
    sec.querySelector('#dbChSelectAll').addEventListener('change', e => {
      const on = e.target.checked;
      allChannels().forEach(c => { if (on && !channelState[c.id]) channelState[c.id] = { choice: 'zscaler', note: '' }; if (!on) delete channelState[c.id]; });
      saveChannelState(channelState); renderChannelsList();
    });
    sec.querySelector('#dbChAdd').addEventListener('click', () => {
      const name = window.prompt('Name the channel or capability to track:'); if (!name || !name.trim()) return;
      const id = 'custom_' + Date.now();
      channelsExtra.push({ id, name: name.trim(), risk: 'medium', category: 'Custom', icon: '🧩', what: 'Added by you; tracked the same way as the built-in channels.' });
      saveExtra(); renderChannelsList(); say(`${name.trim()} added.`);
    });
    sec.querySelector('#dbScopeContinue').addEventListener('click', () => {
      hideScopeView();
      if (typeof _gdGoConfig === 'function') _gdGoConfig(); else if (typeof _stepGo === 'function') _stepGo('configure');
      setCurrent('configure');
    });
    // Assessment Scope and Compliance Frameworks are moved in, not
    // copied: the same live checkboxes runAssessment() already reads.
    const sf = $('scopeField'); if (sf) sec.querySelector('#dbScopeAssessBody').appendChild(sf);
    const fw = $('complianceFwField'); if (fw) sec.querySelector('#dbScopeFwBody').appendChild(fw);
    return sec;
  }
  function channelRowHtml(c) {
    const st = channelState[c.id] || {};
    const addressed = st.choice === 'zscaler' || st.choice === 'alternative';
    return `<div class="db-ch-row ${addressed ? '' : 'gap'}" data-id="${E(c.id)}">
      <label class="db-ch-check"><input type="checkbox" ${addressed ? 'checked' : ''} aria-label="Mark ${E(c.name)} addressed"></label>
      <span class="db-ch-ico" aria-hidden="true">${c.icon}</span>
      <div class="db-ch-body">
        <div class="db-ch-h"><strong>${E(c.name)}</strong><span class="db-chip risk-${RISK_CLS[c.risk] || 'dim'}">${E(RISK_LABEL[c.risk] || c.risk)}</span><span class="db-ch-cat">${E(c.category)}</span></div>
        <p>${E(c.what)}</p>
        ${st.choice === 'alternative' ? `<div class="db-ch-note">${st.note ? `Alternative: ${E(st.note)}` : 'Alternative solution in use'}</div>` : ''}
      </div>
      <div class="db-ch-choice" role="radiogroup" aria-label="${E(c.name)} coverage">
        <label class="db-pill ${st.choice === 'zscaler' ? 'on' : ''}"><input type="radio" name="ch-${E(c.id)}" value="zscaler" ${st.choice === 'zscaler' ? 'checked' : ''}> Zscaler</label>
        <label class="db-pill ${st.choice === 'alternative' ? 'on' : ''}"><input type="radio" name="ch-${E(c.id)}" value="alternative" ${st.choice === 'alternative' ? 'checked' : ''}> Alternative</label>
      </div>
      <button type="button" class="db-ch-edit" title="Note the alternative vendor, or edit a custom channel" aria-label="Edit ${E(c.name)}">✎</button>
      <button type="button" class="db-ch-expand" aria-expanded="false" aria-label="More about ${E(c.name)}">▾</button>
    </div>`;
  }
  function renderChannelsList() {
    const list = $('dbChList'); if (!list) return;
    const items = allChannels();
    list.innerHTML = items.map(channelRowHtml).join('');
    const owned = items.filter(c => (channelState[c.id] || {}).choice === 'zscaler').length;
    const alt = items.filter(c => (channelState[c.id] || {}).choice === 'alternative').length;
    const gaps = items.length - owned - alt;
    const tally = $('dbChFootTxt');
    if (tally) tally.innerHTML = `<strong>${owned + alt} of ${items.length}</strong> addressed (${owned} Zscaler, ${alt} alternative) · <strong>${gaps}</strong> gap${gaps === 1 ? '' : 's'}`;
    const selAll = $('dbChSelectAll'); if (selAll) selAll.checked = items.length > 0 && owned + alt === items.length;
    list.querySelectorAll('.db-ch-row').forEach(row => {
      const id = row.dataset.id;
      row.querySelectorAll('input[type=radio]').forEach(r => r.addEventListener('change', () => {
        channelState[id] = Object.assign({ note: '' }, channelState[id], { choice: r.value });
        saveChannelState(channelState); renderChannelsList(); say(`${allChannels().find(c => c.id === id).name}: ${r.value === 'zscaler' ? 'covered by Zscaler' : 'covered by an alternative'}.`);
      }));
      row.querySelector('.db-ch-check input').addEventListener('change', e => {
        if (e.target.checked) { if (!channelState[id]) { channelState[id] = { choice: 'zscaler', note: '' }; } }
        else { delete channelState[id]; }
        saveChannelState(channelState); renderChannelsList();
      });
      row.querySelector('.db-ch-edit').addEventListener('click', () => {
        const c = allChannels().find(x => x.id === id);
        const note = window.prompt(`Note for ${c.name} (e.g. which alternative vendor is used):`, (channelState[id] || {}).note || '');
        if (note == null) return;
        channelState[id] = Object.assign({ choice: 'alternative' }, channelState[id], { note });
        saveChannelState(channelState); renderChannelsList();
      });
      row.querySelector('.db-ch-expand').addEventListener('click', e => {
        const open = row.classList.toggle('expanded');
        e.target.setAttribute('aria-expanded', String(open)); e.target.textContent = open ? '▴' : '▾';
      });
    });
  }
  const MAIN_CHILD_IDS = ['stepBar', 'gdPanel', 'configPark', 'configCard', 'progressCard', 'results', 'dbLastRun'];
  function showScopeView() {
    if (!scopeView) { scopeView = buildScopeView(); renderChannelsList(); }
    MAIN_CHILD_IDS.forEach(id => { const el = $(id); if (el) el.dataset.dbHiddenFor = 'scope', el.style.display = 'none'; });
    document.querySelector('.hero').hidden = true;
    const foot = $('dbFooter'); if (foot && !foot.hidden) { foot.dataset.dbHiddenFor = 'scope'; foot.hidden = true; }
    scopeView.hidden = false;
    renderChannelsList();
    scopeView.scrollIntoView({ behavior: 'smooth', block: 'start' });
    say('Scope.');
  }
  function hideScopeView() {
    if (!scopeView || scopeView.hidden) return;
    scopeView.hidden = true;
    MAIN_CHILD_IDS.forEach(id => { const el = $(id); if (el && el.dataset.dbHiddenFor === 'scope') { el.style.display = ''; delete el.dataset.dbHiddenFor; } });
    const foot = $('dbFooter'); if (foot && foot.dataset.dbHiddenFor === 'scope') { foot.hidden = false; delete foot.dataset.dbHiddenFor; }
    document.querySelector('.hero').hidden = false;
  }
  window.__dbShowScope = showScopeView;

  // ── Dashboard default content: the space where results render must
  // never sit blank before a fresh run in this tab. Show the selected
  // tenant profile's last recorded assessment (score, maturity, when it
  // ran) when the server has one on file; otherwise a plain prompt that
  // starts the operator on Connect to the tenant. This is a summary of
  // the last run, not a live re-render — the card says so.
  const lastRun = document.createElement('div');
  lastRun.id = 'dbLastRun'; lastRun.className = 'card db-lastrun'; lastRun.hidden = true;
  const progressAnchor = $('progressCard');
  if (progressAnchor) progressAnchor.insertAdjacentElement('beforebegin', lastRun);
  else (document.getElementById('main-content') || container).appendChild(lastRun);
  function renderLastRunOrEmpty() {
    const r = $('results');
    if (r && getComputedStyle(r).display !== 'none') { lastRun.hidden = true; return; }
    const cur = aside.querySelector('.db-item[aria-current="page"]');
    if (!cur || cur.dataset.db !== 'dashboard') { lastRun.hidden = true; return; }
    const det = window.GD && GD.profileDetail;
    const last = det && det.last_assessed;
    if (last) {
      const journey = last.journey ? ` · Journey stage ${last.journey.stage ?? 0} of 5` : '';
      lastRun.innerHTML = `
        <h2>Last assessment</h2>
        <div class="db-lastrun-stats">
          <div class="db-lastrun-stat"><span class="v">${last.score ?? '—'}%</span><span class="k">Score</span></div>
          <div class="db-lastrun-stat"><span class="v">${E(last.maturity || '—')}</span><span class="k">Maturity</span></div>
          <div class="db-lastrun-stat"><span class="v">${last.checks ?? '—'}</span><span class="k">Checks ran</span></div>
          <div class="db-lastrun-stat"><span class="v">${last.critical ?? 0}</span><span class="k">Critical</span></div>
        </div>
        <p class="db-lastrun-meta">Ran ${E(new Date(last.at).toLocaleString())} for ${E(det.name || 'this tenant')}${journey}. Run it again for current results.</p>
        <div class="db-lastrun-actions"><button type="button" class="db-lastrun-btn" id="dbLastRunGo">Run a fresh assessment</button></div>`;
    } else {
      lastRun.innerHTML = `
        <h2>No assessment yet</h2>
        <p>Connect to the tenant, then run the assessment to see the maturity score, completion and findings here.</p>
        <div class="db-lastrun-actions"><button type="button" class="db-lastrun-btn" id="dbLastRunGo">Connect to the tenant &rarr;</button></div>`;
    }
    const go = $('dbLastRunGo');
    if (go) go.addEventListener('click', () => { const btn = aside.querySelector(`.db-item[data-db="${last ? 'run' : 'configure'}"]`); if (btn) btn.click(); });
    lastRun.hidden = false;
  }
  const origProfilesLoad = window._gdProfilesLoad;
  if (typeof origProfilesLoad === 'function') window._gdProfilesLoad = async function () { const r = await origProfilesLoad.apply(this, arguments); renderLastRunOrEmpty(); return r; };

  function setCurrent(k) {
    aside.querySelectorAll('.db-item').forEach(b => { if (b.dataset.db === k) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
    (CONFIG_VIEW_KEYS.has(k) ? showTenantConfig : hideTenantConfig)();
    renderLastRunOrEmpty();
  }
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
    renderLastRunOrEmpty();
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
          <div class="db-tile-t db-tile-t-row">Score Distribution<button type="button" class="db-expand" id="dbRadarExpand" aria-label="Expand Score Distribution to full size" title="Expand to full size">⤢</button></div>
          <div id="dbRadar"></div>
        </div>
      </div>
      <div class="db-pillars" id="dbPillars"></div>
      <div class="db-two">
        <div class="db-tile"><div class="db-tile-t">Key Insights</div><ul class="db-insights" id="dbInsights"></ul></div>
        <div class="db-tile"><div class="db-tile-t">Next actions</div><div class="db-actions" id="dbActions"></div></div>
      </div>`;
    heroCard.querySelector('#dbRadarExpand').addEventListener('click', () => openRadarModal());
  }
  const BAND = ['Ad Hoc', 'Initial', 'Developing', 'Managed', 'Optimized'];   // dlp_assessment_full_auto.maturity(): <25, <50, <75, <90, 90+
  const pctColor = p => p >= 75 ? 'var(--pass)' : p >= 50 ? 'var(--warn)' : 'var(--fail)';
  const level = p => p >= 90 ? ['Optimized', 'ok'] : p >= 75 ? ['Managed', 'ok'] : p >= 50 ? ['Developing', 'warn'] : p >= 25 ? ['Initial', 'fail'] : ['Ad Hoc', 'fail'];
  function ring(id, pct) { const a = $(id); if (!a) return; const C = 2 * Math.PI * 50; a.style.strokeDashoffset = String(C * (1 - Math.max(0, Math.min(100, pct || 0)) / 100)); }
  const SECTION_SHORT = k => k.replace(/^[\d.]+\s*[—-]\s*/, '').replace(/^Ch\.\w+\s*[—-]\s*/, '');
  // The radar's own viewBox is computed from the labels it actually has
  // to draw — never a fixed box — so a long name (or simply enough
  // sections) can never clip past one edge while the other side sits in
  // empty space; the box grows symmetrically, which is what keeps the
  // web centered no matter how many axes there are.
  function radarSvg(sections, { R, charW, fontSize, maxChars, full }) {
    const names = Object.keys(sections || {});
    const n = names.length;
    const pt = (cx, cy, i, r) => { const a = -Math.PI / 2 + (2 * Math.PI * i) / n; return [cx + r * Math.cos(a), cy + r * Math.sin(a)]; };
    const shorts = names.map(k => { const s = SECTION_SHORT(k); return full ? s : s.slice(0, maxChars); });
    const labelR = R + 14;
    // Half-extent big enough for the longest label in the worst-case
    // direction (a label that starts exactly at the label radius and
    // reads straight out), plus the ring itself and a little breathing room.
    const maxLabelPx = Math.max(0, ...shorts.map(s => s.length)) * charW;
    const halfX = labelR + maxLabelPx + 6;
    const halfY = labelR + fontSize + 10;
    const cx = halfX, cy = halfY;
    const web = [0.25, 0.5, 0.75, 1].map(f => `<polygon class="web" points="${names.map((_, i) => pt(cx, cy, i, R * f).map(v => v.toFixed(1)).join(',')).join(' ')}"/>`).join('');
    const spokes = names.map((_, i) => { const [x, y] = pt(cx, cy, i, R); return `<line class="web" x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}"/>`; }).join('');
    const pts = names.map((k, i) => pt(cx, cy, i, R * Math.max(0, Math.min(100, sections[k].pct || 0)) / 100));
    const labels = names.map((k, i) => {
      const [x, y] = pt(cx, cy, i, labelR);
      const anchor = x < cx - 4 ? 'end' : x > cx + 4 ? 'start' : 'middle';
      return `<text x="${x.toFixed(1)}" y="${y.toFixed(1)}" text-anchor="${anchor}" dominant-baseline="middle" font-size="${fontSize}">${E(shorts[i])}${!full && SECTION_SHORT(k).length > maxChars ? '…' : ''}<title>${E(k)}: ${sections[k].pct}%</title></text>`;
    }).join('');
    const pctLabels = full ? pts.map((p, i) => `<text class="db-radar-pct" x="${p[0].toFixed(1)}" y="${(p[1] - 6).toFixed(1)}" text-anchor="middle">${sections[names[i]].pct}%</text>`).join('') : '';
    return `<svg viewBox="0 0 ${(halfX * 2).toFixed(0)} ${(halfY * 2).toFixed(0)}" role="img" aria-label="Score by section: ${E(names.map(k => `${k} ${sections[k].pct}%`).join(', '))}">${web}${spokes}<polygon class="area" points="${pts.map(p => p.map(v => v.toFixed(1)).join(',')).join(' ')}"/>${pts.map(p => `<circle class="pt" cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="${full ? 3.5 : 2.5}"/>`).join('')}${labels}${pctLabels}</svg>`;
  }
  let lastSections = null;
  function radar(sections) {
    const host = $('dbRadar'); if (!host) return;
    lastSections = sections;
    const names = Object.keys(sections || {});
    if (names.length < 3) { host.innerHTML = `<div class="db-comp-s">${names.length ? 'Three or more sections are needed for the radar; the pillar cards below carry the scores.' : 'No sections scored yet.'}</div>`; return; }
    host.innerHTML = radarSvg(sections, { R: 62, charW: 4.6, fontSize: 9, maxChars: 12, full: false });
  }
  function openRadarModal() {
    if (!lastSections || Object.keys(lastSections).length < 3) return;
    let dlg = $('dbRadarModal');
    if (!dlg) {
      dlg = document.createElement('div');
      dlg.id = 'dbRadarModal'; dlg.className = 'db-modal'; dlg.setAttribute('role', 'dialog'); dlg.setAttribute('aria-modal', 'true'); dlg.setAttribute('aria-labelledby', 'dbRadarModalTitle');
      dlg.innerHTML = `<div class="db-modal-card">
        <div class="db-modal-h"><h2 id="dbRadarModalTitle">Score Distribution</h2><button type="button" class="rp-btn" id="dbRadarClose" aria-label="Close">✕ Close</button></div>
        <div id="dbRadarBig"></div>
        <table class="db-radar-legend"><caption class="sr-only">Score by section</caption><thead><tr><th scope="col">Section</th><th scope="col">Score</th></tr></thead><tbody id="dbRadarTbl"></tbody></table>
      </div>`;
      document.body.appendChild(dlg);
      dlg.addEventListener('click', e => { if (e.target === dlg) closeRadarModal(); });
      $('dbRadarClose').addEventListener('click', closeRadarModal);
      document.addEventListener('keydown', e => { if (e.key === 'Escape' && dlg.classList.contains('open')) closeRadarModal(); });
    }
    $('dbRadarBig').innerHTML = radarSvg(lastSections, { R: 220, charW: 6.6, fontSize: 13, maxChars: 999, full: true });
    $('dbRadarTbl').innerHTML = Object.entries(lastSections).map(([k, d]) => `<tr><td>${E(k)}</td><td style="color:${pctColor(d.pct || 0)}">${d.pct}%</td></tr>`).join('');
    dlg.classList.add('open');
    ($('dbRadarClose') || dlg).focus();
    say('Score Distribution, expanded view.');
  }
  function closeRadarModal() {
    const dlg = $('dbRadarModal'); if (!dlg) return;
    dlg.classList.remove('open');
    const btn = document.getElementById('dbRadarExpand'); if (btn) btn.focus();
  }
  const ICONS = [[/ssl|tls/i, '🔒'], [/firewall|fw/i, '🧱'], [/dlp|data|inline|web/i, '🛡️'], [/incident|workflow/i, '🚨'], [/genai|ai\b/i, '🤖'], [/zpa|access/i, '🔑'], [/zcc|client|portal/i, '💻'], [/compliance|regulat/i, '📜'], [/email|mail/i, '✉️'], [/saas|cloud/i, '☁️'], [/endpoint|device/i, '🖥️'], [/log|nss|siem/i, '🧾']];
  const icon = name => (ICONS.find(([re]) => re.test(name || '')) || [null, '📁'])[1];
  function pillars(sections) {
    const host = $('dbPillars'); if (!host) return;
    // Automation Readiness (SDK/OneAPI, Terraform, Ansible, ZPA, ZCC, IaC
    // Hygiene) still runs and still counts toward the overall score; it
    // just doesn't get its own tiles cluttering this grid.
    host.innerHTML = Object.entries(sections || {}).filter(([name]) => !/^Automation — /.test(name)).map(([name, d]) => {
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
