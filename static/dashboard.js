// ── Dashboard layout add-on ──────────────────────────────────────────
// Turns the assessment page into the dashboard look: a left sidebar
// (workflow steps, then every tool the toolbar had, grouped the same
// way; the current tenant; the theme toggle), a compact header, and the
// results drawn as an Overall maturity score ring with the maturity band,
// a Completion ring, a Score distribution radar, one pillar card per
// section, Key insights and action tiles, with the findings as list rows
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
      <button type="button" class="db-item" data-db="scope"><span class="db-ico" aria-hidden="true">🎯</span>Scope assessment</button>
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
  // The floating "? Help" button (guide.js) docks here too, so nothing
  // floats over the findings or the sticky footer.
  const dock = () => {
    const foot = $('dbFoot');
    ['themeToggleBtn', 'bgIntensityControl'].forEach(id => { const el = $(id); if (el && el.parentElement !== foot) foot.appendChild(el); });
    // "? Help" sits in the brand row at the top of the sidebar: always on
    // screen without scrolling the sidebar, never over the content.
    const brand = aside.querySelector('.db-brand'), fab = $('gdHelpFab');
    if (brand && fab && fab.parentElement !== brand) brand.appendChild(fab);
  };
  dock(); setTimeout(dock, 800); setTimeout(dock, 3000);
  // ☰ on narrow screens: a backdrop closes the menu, so does Escape, and
  // the off-canvas sidebar is out of the tab order (dashboard.css).
  const menu = document.createElement('button');
  menu.id = 'dbMenuBtn'; menu.type = 'button'; menu.setAttribute('aria-controls', 'dbSidebar'); menu.setAttribute('aria-expanded', 'false'); menu.innerHTML = '<span aria-hidden="true">☰</span> Menu';
  const setMenu = open => { document.body.classList.toggle('db-open', open); menu.setAttribute('aria-expanded', String(open)); if (!open && document.activeElement && aside.contains(document.activeElement)) menu.focus(); };
  menu.addEventListener('click', () => setMenu(!document.body.classList.contains('db-open')));
  document.body.insertBefore(menu, aside);
  const backdrop = document.createElement('div');
  backdrop.id = 'dbBackdrop'; backdrop.addEventListener('click', () => setMenu(false));
  document.body.insertBefore(backdrop, aside);
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && document.body.classList.contains('db-open')) setMenu(false); });
  // ── Run assessment from the sidebar ─────────────────────────────
  // Sign in first when needed, then run on this page and land on the
  // dashboard (no pop-out tab): missing details → the Connect step opens
  // on the first blank field and the run is queued; not yet authenticated
  // → Authenticate runs, then the assessment; already signed in → run.
  const say = t => { if (typeof announce === 'function') announce(t); };
  const FIELD_LABELS = { org: 'Organization name', assessor: 'Assessor name', vd: 'Vanity domain', cid: 'Client ID', csec: 'Client secret', zuser: 'Admin username', zpass: 'Admin password', zkey: 'API key' };
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
    if (!n) { n = document.createElement('div'); n.id = 'dbRunNote'; n.className = 'db-note'; n.setAttribute('role', 'status'); const sc = aside.querySelector('.db-item[data-db="scope"]'); sc.insertAdjacentElement('afterend', n); }
    n.textContent = text || ''; n.hidden = !text; n.className = 'db-note' + (kind ? ' ' + kind : '');
  }
  let pendingRun = false;
  function goConnect(first) {
    hideScopeView();   // the Scope assessment page steps aside for the sign-in form
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
    // The run happens on the main page: the Scope assessment page steps
    // aside and the progress card (then the results) is where you land.
    if (btn && btn.disabled) { hideScopeView(); setCurrent('dashboard'); const prog = $('progressCard'); if (prog) prog.scrollIntoView({ behavior: 'smooth', block: 'start' }); say('Assessment started. The results open on this page when it finishes.'); }
  }
  async function runFromSidebar() {
    const btn = $('runBtn');
    if (btn && btn.disabled) { say('The assessment is already running.'); return; }
    const missing = missingFields();
    // The organisation and assessor live on the Scope assessment page
    // (report details); everything else is a sign-in detail on Connect.
    const report = missing.filter(id => id === 'org' || id === 'assessor');
    if (report.length) {
      note(`Fill in ${report.map(id => FIELD_LABELS[id] || id).join(' and ')} under Report details, then click Run assessment.`, 'warn');
      say('Fill in the report details first.');
      showScopeView(); setCurrent('scope');
      setTimeout(() => { const el = $(report[0]); if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); el.focus(); } }, 350);
      return;
    }
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
  // Scope, Compliance frameworks) — see below.
  const CONFIG_VIEW_KEYS = new Set(['configure']);
  function showTenantConfig() { const gp = $('gdPanel'); if (gp) gp.hidden = false; const cc = $('configCard'); if (cc) cc.hidden = false; }
  function hideTenantConfig() { const gp = $('gdPanel'); if (gp) gp.hidden = true; const cc = $('configCard'); if (cc) cc.hidden = true; }
  hideTenantConfig();
  const origGoConfig = window._gdGoConfig;
  if (typeof origGoConfig === 'function') window._gdGoConfig = function () { showTenantConfig(); return origGoConfig.apply(this, arguments); };

  // Workflow items: the same routes as the step strip, except Run.
  aside.querySelectorAll('.db-item').forEach(b => b.addEventListener('click', () => {
    const k = b.dataset.db;
    setMenu(false);
    if (k === 'scope') { showScopeView(); setCurrent('scope'); return; }
    hideScopeView();
    if (k === 'dashboard') { const r = $('results'); if (r && getComputedStyle(r).display !== 'none') r.scrollIntoView({ behavior: 'smooth', block: 'start' }); else window.scrollTo({ top: 0, behavior: 'smooth' }); setCurrent('dashboard'); return; }
    if (typeof _stepGo === 'function') _stepGo(k);
    setCurrent(k);
  }));
  // Every "Run assessment" (the Scope assessment page's button, the step
  // strip, the guide's steps 2 and 7) funnels into this same runner, so a
  // run always behaves the same way.
  window.__dbRunFromSidebar = runFromSidebar;
  window.__dbNote = note;

  // ── Scope: one combined page for everything that decides what the
  // assessment covers — which Zscaler data-security channels the
  // customer already owns (versus an alternative, versus a gap), which
  // parts of the platform to check, and which compliance frameworks the
  // report should map to. Channel ownership is a one-time input (there
  // is no API for "what does the customer already own"), kept in this
  // browser; Assessment scope and Compliance frameworks are the same
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
  const RISK_LABEL = { critical: 'Critical risk', high: 'High risk', medium: 'Medium risk', low: 'Low risk' };
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
      <div class="hero db-ch-hero"><h1><span aria-hidden="true">🎯</span> Scope assessment</h1>
        <p>What this assessment covers and who it is for: the Zscaler data-security channels the customer already runs, which parts of the platform to check, which compliance frameworks the report should map to, and the organisation and assessor on the report cover. Then run it from here; sign-in details stay under Connect to the tenant.</p></div>
      <div class="card db-scope-section" id="dbScopeChannelsCard">
        <div class="db-scope-section-h">
          <h2>Channels <span class="db-scope-tally" id="dbChFootTxt"></span></h2>
          <div class="db-ch-bar">
            <label class="df-ctl"><input type="checkbox" id="dbChSelectAll"> <span class="lbl">Select all</span></label>
            <span class="sep"></span>
            <button type="button" class="rp-btn primary" id="dbChAdd">+ Add channel</button>
          </div>
        </div>
        <p class="db-scope-p">Which Zscaler data security channels the customer owns. <strong>Zscaler</strong>: the assessment reads it. <strong>Alternative</strong>: another product covers it, so its checks are reported as <em>Not in scope</em> and left out of the score (note the vendor with ✎). <strong>Unticked</strong>: a gap; the assessment still reads the tenant and the findings show what is missing. The declaration is saved with the tenant profile and printed in the report.</p>
        <div id="dbChList" class="db-ch-list"></div>
      </div>
      <div class="card db-scope-section" id="dbScopeAssessCard"><div id="dbScopeAssessBody"></div></div>
      <div class="card db-scope-section" id="dbScopeFwCard"><div id="dbScopeFwBody"></div></div>
      <div class="card db-scope-section" id="dbScopeReportCard">
        <div class="db-scope-section-h"><h2>Report details</h2></div>
        <p class="db-scope-p">Who the report is for and who ran it; both print on the cover.</p>
        <div class="form-grid" id="dbScopeReportBody"></div>
      </div>
      <div class="db-scope-foot">
        <button type="button" class="rp-btn primary" id="dbScopeRun">▶ Run assessment</button>
        <span class="db-scope-p">Signs in first when needed. The assessment runs on this page; the results open on the Dashboard.</span>
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
    sec.querySelector('#dbScopeRun').addEventListener('click', () => { runFromSidebar(); });
    // Assessment scope, Compliance frameworks and the report details
    // (organisation, assessor) are moved in, not copied: the same live
    // fields runAssessment() already reads. The tenant configuration card
    // keeps the sign-in details only.
    const sf = $('scopeField'); if (sf) sec.querySelector('#dbScopeAssessBody').appendChild(sf);
    const fw = $('complianceFwField'); if (fw) sec.querySelector('#dbScopeFwBody').appendChild(fw);
    ['org', 'assessor'].forEach(id => { const el = $(id); const field = el && el.closest('.field'); if (field) sec.querySelector('#dbScopeReportBody').appendChild(field); });
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
  // What the assessment and the tenant profile read: every channel with its
  // choice (zscaler / alternative / gap), note and name (channel_scope.py
  // applies it: an "alternative" channel's checks are reported as not in
  // scope). A profile's saved declaration replaces this browser's copy.
  window.__dbChannelScope = function () {
    const out = {};
    allChannels().forEach(c => { const st = channelState[c.id] || {}; out[c.id] = { choice: st.choice === 'zscaler' || st.choice === 'alternative' ? st.choice : 'gap', note: st.note || '', name: c.name }; });
    return out;
  };
  window.__dbChannelsSet = function (declared) {
    if (!declared || typeof declared !== 'object') return;
    const next = {};
    Object.entries(declared).forEach(([id, v]) => {
      if (!v || typeof v !== 'object') return;
      if (v.choice === 'zscaler' || v.choice === 'alternative') next[id] = { choice: v.choice, note: String(v.note || '') };
      if (!allChannels().some(c => c.id === id) && String(id).startsWith('custom_') && v.name) {
        channelsExtra.push({ id, name: String(v.name), risk: 'medium', category: 'Custom', icon: '🧩', what: 'Added by you; tracked the same way as the built-in channels.' });
      }
    });
    channelState = next; saveChannelState(channelState); saveExtra();
    if (scopeView) renderChannelsList();
  };
  const MAIN_CHILD_IDS = ['stepBar', 'gdPanel', 'configPark', 'configCard', 'dbHero', 'progressCard', 'results', 'dbLastRun'];
  function showScopeView() {
    if (!scopeView) { scopeView = buildScopeView(); renderChannelsList(); }
    MAIN_CHILD_IDS.forEach(id => { const el = $(id); if (el) el.dataset.dbHiddenFor = 'scope', el.style.display = 'none'; });
    document.querySelector('.hero').hidden = true;
    const foot = $('dbFooter'); if (foot && !foot.hidden) { foot.dataset.dbHiddenFor = 'scope'; foot.hidden = true; }
    scopeView.hidden = false;
    renderChannelsList();
    scopeView.scrollIntoView({ behavior: 'smooth', block: 'start' });
    say('Scope assessment.');
  }
  function hideScopeView() {
    if (!scopeView || scopeView.hidden) return;
    scopeView.hidden = true;
    MAIN_CHILD_IDS.forEach(id => { const el = $(id); if (el && el.dataset.dbHiddenFor === 'scope') { el.style.display = ''; delete el.dataset.dbHiddenFor; } });
    const foot = $('dbFooter'); if (foot && foot.dataset.dbHiddenFor === 'scope') { foot.hidden = false; delete foot.dataset.dbHiddenFor; }
    document.querySelector('.hero').hidden = false;
  }
  window.__dbShowScope = showScopeView;
  // Built at load (hidden) so the report details leave the tenant
  // configuration card before anyone opens Connect to the tenant.
  scopeView = buildScopeView(); renderChannelsList();

  // ── Dashboard default content: the score tiles (ring, completion,
  // radar, pillars, insights, actions) live outside #results so they are
  // always on screen, even before a fresh run in this tab — never blank.
  // This slim note sits above them: the selected tenant profile's last
  // recorded assessment (score, maturity, when it ran), lightly filled
  // into the ring itself, when the server has one on file; otherwise a
  // plain prompt that starts the operator on Connect to the tenant. Kept
  // deliberately free of the ring/band helpers defined further down (the
  // hero section), since this runs from the very first refreshCurrent()
  // call, before those exist.
  const lastRun = document.createElement('div');
  lastRun.id = 'dbLastRun'; lastRun.className = 'db-note db-lastrun-note'; lastRun.hidden = true;
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
      // A previous result is shown as exactly that — labelled with its run
      // time — and a run that scored nothing shows "—", not 0%.
      const measured = last.score !== null && last.score !== undefined && Number.isFinite(Number(last.score));
      const score = measured ? Math.max(0, Math.min(100, Number(last.score))) : null;
      const arc = $('dbRingArc'); if (arc) { const C = 2 * Math.PI * 50; arc.style.strokeDashoffset = String(measured ? C * (1 - score / 100) : C); }
      const bandHost = $('dbBand');
      if (bandHost && measured) {
        const idx = score >= 90 ? 4 : score >= 75 ? 3 : score >= 50 ? 2 : score >= 25 ? 1 : 0;
        bandHost.innerHTML = ['Ad Hoc', 'Initial', 'Developing', 'Managed', 'Optimized'].map((b, i) => `<span class="${i < idx ? 'done' : i === idx ? 'now' : ''}" ${i === idx ? 'aria-current="true"' : ''}>${b}</span>`).join('');
      } else if (bandHost) bandHost.innerHTML = '';
      const sn = $('scoreNum'); if (sn) sn.textContent = measured ? `${score}%` : '—';
      const sl = $('scoreLabel'); if (sl) sl.textContent = last.maturity || (measured ? 'Maturity level' : 'Not assessed');
      const sm = $('scoreMeta'); if (sm) sm.textContent = `Previous result · run ${new Date(last.at).toLocaleString()}`;
      const cp = $('dbCompPct'), ct = $('dbCompTxt');
      if (cp) cp.textContent = '—';
      if (ct) ct.textContent = `last run: ${last.checks ?? '?'} checks`;
      const journey = last.journey ? ` · journey stage ${last.journey.stage ?? 0} of 5` : '';
      lastRun.innerHTML = `<span>Showing the last recorded assessment for ${E(det.name || 'this tenant')}, run ${E(new Date(last.at).toLocaleString())}${journey}.</span> <button type="button" class="db-lastrun-btn" id="dbLastRunGo">Run a fresh assessment</button>`;
    } else {
      lastRun.innerHTML = `<span>No assessment recorded yet for this tenant — the tiles below fill in once you run one.</span> <button type="button" class="db-lastrun-btn" id="dbLastRunGo">Connect to the tenant &rarr;</button>`;
    }
    const go = $('dbLastRunGo');
    if (go) go.addEventListener('click', () => { const btn = aside.querySelector(`.db-item[data-db="${last ? 'scope' : 'configure'}"]`); if (btn) btn.click(); });
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
    // The Scope assessment page's Run button follows the real run button.
    const run = $('dbScopeRun'), btn = $('runBtn');
    if (run && btn) { const busy = !!btn.disabled; run.disabled = busy; run.setAttribute('aria-busy', String(busy)); run.textContent = busy ? '⏳ Running…' : '▶ Run assessment'; }
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
          <h3 class="db-tile-t">Overall maturity score</h3>
          <div class="db-ring">
            <svg viewBox="0 0 120 120" role="img" aria-labelledby="dbRingLbl"><title id="dbRingLbl">Overall maturity score</title>
              <defs><linearGradient id="dbRingGrad" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3b82f6"/><stop offset="0.6" stop-color="#22d3ee"/><stop offset="1" stop-color="#a78bfa"/></linearGradient></defs>
              <circle class="track" cx="60" cy="60" r="50"/><circle class="arc" id="dbRingArc" cx="60" cy="60" r="50" stroke-dasharray="314.16" stroke-dashoffset="314.16"/>
            </svg>
            <div class="db-ring-txt">
              <div class="score-num" id="scoreNum">—</div>
              <div class="score-label" id="scoreLabel">Not assessed yet</div>
              <div class="score-meta" id="scoreMeta"></div>
            </div>
          </div>
          <div class="db-band" id="dbBand" aria-label="Maturity band"></div>
        </div>
        <div class="db-tile">
          <h3 class="db-tile-t">Completion</h3>
          <div class="db-ring small">
            <svg viewBox="0 0 120 120" role="img" aria-labelledby="dbCompLbl"><title id="dbCompLbl">Assessment completion</title>
              <circle class="track" cx="60" cy="60" r="50"/><circle class="arc" id="dbCompArc" cx="60" cy="60" r="50" stroke-dasharray="314.16" stroke-dashoffset="314.16"/>
            </svg>
            <div class="db-ring-txt"><div class="db-comp-n" id="dbCompPct">—</div><div class="db-comp-s" id="dbCompTxt">no run in this tab yet</div></div>
          </div>
        </div>
        <div class="db-tile db-radar">
          <h3 class="db-tile-t db-tile-t-row">Score by section<button type="button" class="db-expand" id="dbRadarExpand" aria-label="Show the scores by section as a radar, full size" title="Radar view, full size (three or more measured sections)">⤢</button></h3>
          <div id="dbRadar"></div>
        </div>
      </div>
      <div class="db-pillars" id="dbPillars"></div>
      <div class="db-two">
        <div class="db-tile"><h3 class="db-tile-t">Key insights</h3><ul class="db-insights" id="dbInsights"></ul></div>
        <div class="db-tile"><h3 class="db-tile-t">Next actions</h3><div class="db-actions" id="dbActions"></div></div>
      </div>`;
    heroCard.querySelector('#dbRadarExpand').addEventListener('click', () => openRadarModal());
    // Moved out of #results (not copied) so the tiles are always on
    // screen, at their zero state or the last recorded assessment,
    // instead of sitting behind the same display:none that hides the
    // findings list and download bar until a fresh run finishes. The
    // mirrored results tab (tool_tabs.js) is told about the new id so
    // "Open in new tab" still carries the hero into that tab.
    heroCard.id = 'dbHero';
    heroCard.setAttribute('role', 'region'); heroCard.setAttribute('aria-label', 'Dashboard: score, completion, sections, insights and next actions');
    lastRun.insertAdjacentElement('afterend', heroCard);
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
    // Only measured sections are drawn: an unmeasured one (pct null) has no
    // point on the web, and the legend below the full view says "—" for it.
    const names = Object.keys(sections || {}).filter(k => sections[k] && sections[k].pct !== null && sections[k].pct !== undefined);
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
  const measuredNames = s => Object.keys(s || {}).filter(k => s[k] && s[k].pct !== null && s[k].pct !== undefined);
  // The tile's primary view is a plain list of bars — one row per section,
  // readable at any width and by a screen reader — and the radar is the
  // optional expanded view behind the ⤢ button (three or more measured
  // sections; a radar with fewer has no shape to read).
  function radar(sections) {
    const host = $('dbRadar'); if (!host) return;
    lastSections = sections;
    const entries = Object.entries(sections || {});
    const btn = $('dbRadarExpand'); if (btn) btn.disabled = measuredNames(sections).length < 3;
    if (!entries.length) { host.innerHTML = '<div class="db-comp-s">No sections scored yet.</div>'; return; }
    host.innerHTML = `<ol class="db-secbars" aria-label="Score by section">${entries.map(([k, d]) => {
      const m = d.pct !== null && d.pct !== undefined;
      return `<li><span class="n" title="${E(k)}">${E(SECTION_SHORT(k))}</span><span class="b" aria-hidden="true"><i style="width:${m ? Math.max(0, Math.min(100, d.pct)) : 0}%;background:${m ? pctColor(d.pct) : 'transparent'}"></i></span><span class="p" style="color:${m ? pctColor(d.pct) : 'var(--dim)'}">${m ? d.pct + '%' : '—'}</span><span class="sr-only">${m ? '' : ' not measured'}</span></li>`;
    }).join('')}</ol>`;
  }
  function openRadarModal() {
    if (!lastSections || measuredNames(lastSections).length < 3) return;
    let dlg = $('dbRadarModal');
    if (!dlg) {
      dlg = document.createElement('div');
      dlg.id = 'dbRadarModal'; dlg.className = 'db-modal'; dlg.setAttribute('role', 'dialog'); dlg.setAttribute('aria-modal', 'true'); dlg.setAttribute('aria-labelledby', 'dbRadarModalTitle');
      dlg.innerHTML = `<div class="db-modal-card">
        <div class="db-modal-h"><h2 id="dbRadarModalTitle">Score distribution</h2><button type="button" class="rp-btn" id="dbRadarClose" aria-label="Close">✕ Close</button></div>
        <div id="dbRadarBig"></div>
        <table class="db-radar-legend"><caption class="sr-only">Score by section</caption><thead><tr><th scope="col">Section</th><th scope="col">Score</th></tr></thead><tbody id="dbRadarTbl"></tbody></table>
      </div>`;
      document.body.appendChild(dlg);
      dlg.addEventListener('click', e => { if (e.target === dlg) closeRadarModal(); });
      $('dbRadarClose').addEventListener('click', closeRadarModal);
      document.addEventListener('keydown', e => { if (e.key === 'Escape' && dlg.classList.contains('open')) closeRadarModal(); });
    }
    $('dbRadarBig').innerHTML = radarSvg(lastSections, { R: 220, charW: 6.6, fontSize: 13, maxChars: 999, full: true });
    $('dbRadarTbl').innerHTML = Object.entries(lastSections).map(([k, d]) => { const m = d.pct !== null && d.pct !== undefined; return `<tr><td>${E(k)}</td><td style="color:${m ? pctColor(d.pct) : 'var(--dim)'}">${m ? d.pct + '%' : 'Not measured'}</td></tr>`; }).join('');
    dlg.classList.add('open');
    ($('dbRadarClose') || dlg).focus();
    say('Score distribution, expanded view.');
  }
  function closeRadarModal() {
    const dlg = $('dbRadarModal'); if (!dlg) return;
    dlg.classList.remove('open');
    const btn = document.getElementById('dbRadarExpand'); if (btn) btn.focus();
  }
  // One symbol per section family (icons.js), used by the pillar tiles and
  // the findings rows; the emoji is only the fallback when icons.js is absent.
  const ICONS = [[/ssl|tls/i, 'lock', '🔒'], [/firewall|fw/i, 'bricks', '🧱'], [/dlp|data|inline|web/i, 'shield', '🛡️'], [/incident|workflow/i, 'siren', '🚨'], [/genai|ai\b/i, 'cpu', '🤖'], [/zpa|access/i, 'key', '🔑'], [/zcc|client|portal/i, 'laptop', '💻'], [/compliance|regulat/i, 'scroll', '📜'], [/email|mail/i, 'envelope', '✉️'], [/saas|cloud/i, 'cloud', '☁️'], [/endpoint|device/i, 'desktop', '🖥️'], [/log|nss|siem/i, 'receipt', '🧾']];
  const iconName = name => (ICONS.find(([re]) => re.test(name || '')) || [null, 'folder', '📁']);
  const icon = name => { const [, sym, emoji] = iconName(name); return (typeof window.dlpIcon === 'function' && window.dlpIcon(sym)) || emoji; };
  function pillars(sections) {
    const host = $('dbPillars'); if (!host) return;
    // Automation readiness (SDK/OneAPI, Terraform, Ansible, ZPA, ZCC, IaC
    // Hygiene) still runs and still counts toward the overall score; it
    // just doesn't get its own tiles cluttering this grid.
    host.innerHTML = Object.entries(sections || {}).filter(([name]) => !/^Automation — /.test(name)).map(([name, d]) => {
      const scored = (d.scored !== undefined) ? d.scored : (d.total || 0) - (d.info || 0);
      const measured = scored > 0 && d.pct !== null && d.pct !== undefined;
      if (!measured) {
        // Nothing scoreable here (every result informational, not permitted
        // or unable to run): no percentage and no level, never "100% Optimized".
        return `<button type="button" class="db-pillar db-pillar-na" data-section="${E(name)}" aria-label="${E(name)}: not measured, ${d.total || 0} checks outside the score. Show these findings.">
          <div class="db-pillar-h"><span class="db-pillar-n"><span aria-hidden="true">${icon(name)}</span> ${E(name)}</span><span class="db-pillar-p db-pillar-p-na">—</span></div>
          <div class="db-bar"><i style="width:0"></i></div>
          <div class="db-pillar-m"><span>no scoreable check · ${d.total || 0} outside the score</span><span class="db-chip na">Not measured</span></div>
        </button>`;
      }
      const [lv, cls] = level(d.pct);
      return `<button type="button" class="db-pillar" data-section="${E(name)}" aria-label="${E(name)}: ${d.pct}%, ${d.pass || 0} of ${scored} configured, ${lv}. Show these findings.">
        <div class="db-pillar-h"><span class="db-pillar-n"><span aria-hidden="true">${icon(name)}</span> ${E(name)}</span><span class="db-pillar-p" style="color:${pctColor(d.pct)}">${d.pct}%</span></div>
        <div class="db-bar"><i style="width:${Math.max(0, Math.min(100, d.pct))}%"></i></div>
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
    // Only measured sections can be weakest or strongest: an unmeasured one
    // (pct null, nothing scoreable) is neither.
    const secs = Object.entries(data.sections || {}).filter(([, d]) => d.pct !== null && d.pct !== undefined && ((d.scored !== undefined ? d.scored : (d.total || 0) - (d.info || 0)) > 0));
    const weakest = secs.slice().sort((a, b) => (a[1].pct || 0) - (b[1].pct || 0))[0];
    const strongest = secs.slice().sort((a, b) => (b[1].pct || 0) - (a[1].pct || 0))[0];
    const items = [];
    if (fails.length) items.push(['fail', '⚠️', `<strong>${fails.length} finding${fails.length === 1 ? '' : 's'} need action.</strong> First: ${E(fails[0].label)}${fails[0].plain && fails[0].plain.means ? ` — ${E(fails[0].plain.means)}` : ''}`]);
    if (weakest && weakest[1].pct < 75) items.push(['warn', '📉', `<strong>Weakest area: ${E(weakest[0])}</strong> at ${weakest[1].pct}% (${weakest[1].fail || 0} to fix, ${weakest[1].warn || 0} to review).`]);
    if (reviews.length) items.push(['warn', '🔎', `<strong>${reviews.length} item${reviews.length === 1 ? '' : 's'} to review</strong> with the customer: they are configured, but not the way Zscaler recommends.`]);
    if (strongest && strongest[1].pct >= 75) items.push(['ok', '✅', `<strong>Strongest area: ${E(strongest[0])}</strong> at ${strongest[1].pct}%; ${strongest[1].pass || 0} checks configured.`]);
    if (data.permissions && data.permissions.blocked) items.push(['warn', '🔏', `<strong>${data.permissions.blocked} check${data.permissions.blocked === 1 ? '' : 's'} could not run</strong>: the API client's role lacks their feature. The card below says what to grant.`]);
    // The Scope page's channel declaration, as the server applied it.
    const cc = data.channel_coverage;
    if (cc && cc.declared) {
      const alt = cc.alternative || [], gaps = cc.gaps || [];
      const altTxt = alt.length ? `${alt.length} covered elsewhere (${alt.map(a => E(a.name) + (a.note ? ` — ${E(a.note)}` : '')).join(', ')}; ${cc.not_in_scope || 0} check${cc.not_in_scope === 1 ? '' : 's'} not in scope)` : '';
      const gapTxt = gaps.length ? `${gaps.length} gap${gaps.length === 1 ? '' : 's'} (${gaps.map(g => E(g.name)).join(', ')})` : 'no gaps';
      items.push([gaps.length ? 'warn' : 'ok', '🎯', `<strong>Channels: ${(cc.zscaler || []).length} on Zscaler</strong>${altTxt ? `, ${altTxt}` : ''}, ${gapTxt}. Declared on the Scope page.`]);
    }
    if (!items.length) items.push(['ok', '✅', `<strong>${passes.length} of ${checks.length} checks configured.</strong> Nothing needs action.`]);
    host.innerHTML = items.slice(0, 5).map(([cls, ico, html]) => `<li class="${cls}"><span class="db-ico" aria-hidden="true">${ico}</span><span>${html}</span></li>`).join('');
  }
  function actions(data) {
    const host = $('dbActions'); if (!host) return;
    const open = (data.checks || []).filter(c => c.status === 'FAIL' || c.status === 'REVIEW');
    const fails = open.filter(c => c.status === 'FAIL').length;
    // "with a recipe" is the same matcher the findings rows use; when the
    // catalogue is not loaded yet the tile says only what it knows.
    const withRecipe = (typeof _findRecipeForCheck === 'function' && window._remediationCatalog) ? open.filter(c => _findRecipeForCheck(c.id)).length : null;
    const A = [
      ['🔧', 'Review & remediate', fails ? `${fails} to fix${withRecipe !== null ? ` · ${withRecipe} with a one-click recipe` : ''}` : 'nothing to fix', () => typeof openRemediationReview === 'function' && openRemediationReview()],
      ['🗺️', 'Traffic flow & gaps', 'where inspection is lost', () => typeof openDataFlowTab === 'function' && openDataFlowTab()],
      ['📄', 'Generate report', 'Word document for the customer', () => typeof downloadDocx === 'function' && downloadDocx()],
      ['📦', 'Deploy a policy pack', 'close the gaps, preflight first', () => typeof openDlpPacksModal === 'function' && openDlpPacksModal()],
      ['🧭', 'Path analyzer', 'what blocks one destination', () => typeof openPathAnalyzerTab === 'function' && openPathAnalyzerTab()],
      ['🔁', 'Start a new assessment', 'clears these results, then run again', () => typeof resetForm === 'function' && resetForm()],
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
      <button type="button" class="db-foot-btn" id="dbFootBtn">${gaps ? 'Continue to review & remediate →' : 'Generate the report →'}</button>`;
    $('dbFootBtn').addEventListener('click', () => { if (gaps && typeof openRemediationReview === 'function') openRemediationReview(); else if (typeof downloadDocx === 'function') downloadDocx(); });
    f.hidden = false;
    document.body.classList.add('db-has-footer');
  }
  function decorateChecks() {
    document.querySelectorAll('#checksList .check-item').forEach(row => {
      if (row.dataset.decorated) return;
      row.dataset.decorated = '1';
      const hdr = row.previousElementSibling && row.previousElementSibling.classList.contains('section-header') ? row.previousElementSibling : (() => { let p = row.previousElementSibling; while (p && !p.classList.contains('section-header')) p = p.previousElementSibling; return p; })();
      const sec = hdr ? hdr.textContent.trim() : '';
      // A real element (screen readers skip it) rather than CSS generated
      // text, which most of them read aloud.
      row.dataset.ico = '';
      row.insertAdjacentHTML('afterbegin', `<span class="db-row-ico" aria-hidden="true">${icon(sec)}</span>`);
      const st = row.querySelector('.check-status');
      if (st && !st.title) { const risk = { 'Action required': ['High risk', 'status-FAIL'], 'Needs review': ['Medium risk', 'status-REVIEW'], 'Not configured': ['Low risk', 'status-INFO'], 'Configured': ['Configured', 'status-PASS'] }[st.textContent.trim()]; if (risk) st.title = `${st.textContent.trim()} · ${risk[0]}`; }
      const label = row.querySelector('.check-label');
      if (label && sec && !row.querySelector('.db-cat')) label.insertAdjacentHTML('afterend', `<span class="db-cat">${E(sec)}</span>`);
    });
  }
  // One vocabulary (index.html assessmentSummary / permissions.assessment_summary,
  // docs/SCORING.md): execution completion and score coverage are two numbers.
  const summaryOf = data => (typeof assessmentSummary === 'function') ? assessmentSummary(data) : (data.summary || { total: (data.checks || []).length, assessed: (data.checks || []).length, not_permitted: 0, errors: 0, score: data.score, state: 'complete' });
  function renderDashboard(data) {
    const sum = summaryOf(data);
    const measured = sum.score !== null && sum.score !== undefined && Number.isFinite(Number(sum.score));
    const score = measured ? Number(sum.score) : null;
    ring('dbRingArc', measured ? score : 0);
    if (measured) band(score); else { const b = $('dbBand'); if (b) b.innerHTML = ''; }
    // Completion is about execution only: the run is finished, this is what
    // ran and what the API client was not permitted to run. Never a
    // percentage that mixes "finished" with "allowed".
    ring('dbCompArc', 100);
    const cp = $('dbCompPct'), ct = $('dbCompTxt');
    if (cp) cp.textContent = sum.state === 'partial' ? 'Partial' : 'Done';
    const extra = [sum.not_permitted ? `${sum.not_permitted} not permitted` : '', sum.not_in_scope ? `${sum.not_in_scope} not in scope` : '', sum.errors ? `${sum.errors} could not be checked` : ''].filter(Boolean);
    if (ct) ct.textContent = (sum.not_permitted || sum.not_in_scope)
      ? `${sum.assessed} of ${sum.total} assessed · ${extra.join(' · ')}`
      : `${sum.total} checks assessed${sum.errors ? ` · ${sum.errors} could not be checked` : ''}`;
    radar(data.sections); pillars(data.sections); insights(data); actions(data); footer(data); decorateChecks();
    const s = $('dbCurScore'); if (s) s.textContent = measured ? `${score}% · ${data.maturity || level(score)[0]}` : 'Not assessed';
    // The results are on screen: Findings & report is the current item
    // (set here, not left to the step-strip observer's timing).
    setCurrent('review');
  }
  // While a run is in flight the tiles say so — the Completion tile follows
  // the same progress events as the progress card (index.html handleEvent),
  // and a previous score stays visible only labelled as previous.
  window.__dbRunStarted = function () {
    const cp = $('dbCompPct'), ct = $('dbCompTxt'); if (cp) cp.textContent = '0%'; if (ct) ct.textContent = 'starting…';
    ring('dbCompArc', 0);
    const sm = $('scoreMeta'), sn = $('scoreNum');
    if (sm) sm.textContent = (sn && sn.textContent !== '—') ? 'Assessing now · previous result shown until it finishes' : 'Assessing now';
    const f = $('dbFooter'); if (f) f.hidden = true; document.body.classList.remove('db-has-footer');
  };
  window.__dbProgress = function (evt) {
    if (!evt || evt.total === undefined || evt.completed === undefined) return;
    const pct = evt.pct || Math.round(evt.completed / evt.total * 100);
    ring('dbCompArc', pct);
    const cp = $('dbCompPct'), ct = $('dbCompTxt');
    if (cp) cp.textContent = `${pct}%`;
    if (ct) ct.textContent = evt.journey ? `all ${evt.total} checks done · measuring the journey` : `${evt.completed} of ${evt.total} checks run`;
  };
  // Wrap the inline script's entry points (top-level function declarations are window properties).
  const origShow = window.showResults, origRender = window.renderChecks, origReset = window.resetForm;
  if (typeof origShow === 'function') window.showResults = function (data) { origShow.apply(this, arguments); try { renderDashboard(data || {}); } catch (e) { console.error('dashboard', e); } };
  if (typeof origRender === 'function') window.renderChecks = function () { origRender.apply(this, arguments); try { decorateChecks(); } catch (e) { /* cosmetic */ } };
  if (typeof origReset === 'function') window.resetForm = function () { origReset.apply(this, arguments); const f = $('dbFooter'); if (f) f.hidden = true; document.body.classList.remove('db-has-footer'); setCurrent('configure'); };
  window.__dbRender = renderDashboard;
})();
