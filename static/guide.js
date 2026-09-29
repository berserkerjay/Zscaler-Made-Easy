// ── Guide: Start-here panel, Guided mode, Test connection, Help drawer ──
// Injected by the server after index.html's inline script. Everything here
// is additive: it reads the page's existing controls (tenant fields, the
// Run Assessment button, the results card, Deploy Studio) and explains
// them in plain language so a first-time operator can follow the four
// steps without knowing ZIA DLP internals.

const GD = { conn: null, testing: false, mode: 'guided', helpOpen: false, timer: null,
             profile: '', profileHasSecret: false, profiles: [], profileDetail: null, profileBusy: false, packs: [] };
// A top-level const is not a window property: the page's own script and
// Deploy Studio look for window.GD (the selected profile, its remembered
// secret), and without this line they never found it, so a remembered
// secret was never used from the browser.
window.GD = GD;
const GD_LS_PROFILE = 'zassess_profile';
const GD_LS_MODE = 'zassess_guide_mode';
const GD_LS_CONN = 'zassess_guide_conn';
const GD_LS_DEPLOY = 'zassess_last_deploy';

const _gdE = s => (typeof escapeHtml === 'function' ? escapeHtml(String(s == null ? '' : s)) : String(s == null ? '' : s));
const _gdVal = id => ((document.getElementById(id) || {}).value || '').trim();

function _gdLoad() {
  try {
    GD.mode = localStorage.getItem(GD_LS_MODE) || 'guided';
    GD.profile = localStorage.getItem(GD_LS_PROFILE) || '';
    const c = localStorage.getItem(GD_LS_CONN); if (c) GD.conn = JSON.parse(c);
  } catch (e) { /* storage may be unavailable */ }
}
function _gdSave() {
  try {
    localStorage.setItem(GD_LS_MODE, GD.mode);
    localStorage.setItem(GD_LS_PROFILE, GD.profile || '');
    if (GD.conn) localStorage.setItem(GD_LS_CONN, JSON.stringify(GD.conn));
  } catch (e) { /* ignore */ }
}

// ── Step state ────────────────────────────────────────────────────
function _gdSteps() {
  // Either sign-in (see tenant_auth.py): a ZIdentity API client, or the
  // classic ZIA API's admin username, password and API key.
  const legacy = (document.getElementById('authMethod') || {}).value === 'legacy';
  const remembered = !!(GD.profile && GD.profileHasSecret);
  const creds = legacy
    ? !!(_gdVal('zuser') && ((_gdVal('zpass') && _gdVal('zkey')) || remembered))
    : !!(_gdVal('vd') && _gdVal('cid') && (_gdVal('csec') || remembered));
  const sameTenant = GD.conn && GD.conn.vd === (legacy ? _gdVal('zuser') : _gdVal('vd'));
  const connected = !!(sameTenant && GD.conn.ok);
  const runBtn = document.getElementById('runBtn');
  const running = !!(runBtn && runBtn.disabled);
  const results = document.getElementById('results');
  const assessed = !!(results && results.offsetParent !== null && results.textContent.trim().length > 50);
  let deployed = null;
  try { deployed = JSON.parse(localStorage.getItem(GD_LS_DEPLOY) || 'null'); } catch (e) { /* ignore */ }
  return [
    {
      n: 1, title: 'Connect to the tenant',
      state: sameTenant && GD.conn.ok ? 'done' : (creds ? 'ready' : 'todo'),
      what: legacy
        ? 'Open Tenant details below, pick the tenant\'s cloud, enter the admin username, password and the tenant\'s API key, and click Authenticate. Nothing is changed in the tenant; the tool only reads.'
        : 'Open Tenant details below, enter the customer\'s cloud, vanity domain, API client ID and client secret, and click Authenticate. Nothing is changed in the tenant; the tool only reads.',
      need: legacy
        ? 'The classic ZIA API: a ZIA admin allowed to use the API (username and password) and the tenant\'s API key from Administration > API Key Management. Covers ZIA only. For a tenant on ZIdentity, switch the sign-in method to OneAPI.'
        : 'A OneAPI API client from ZIdentity (Integration > API Clients) with a ZIA role that can read DLP dictionaries, engines and rules. Ask the customer\'s Zscaler admin for these four values. A tenant without ZIdentity can use the classic ZIA API instead (sign-in method in Tenant details).',
      status: sameTenant && GD.conn.ok
        ? `Connected to ${_gdE(GD.conn.label)}: ${GD.conn.dictionaries} dictionaries, ${GD.conn.engines} engines, ${GD.conn.web_rules} web DLP rules.`
        : (creds ? 'Details entered. Click Authenticate before going further.' : 'Fill in the tenant fields, then click Authenticate.'),
      tenant: true,
      actions: [
        { label: 'Show tenant details', fn: '_gdGoConfig()', kind: creds ? 'quiet' : 'primary' },
        { label: GD.testing ? 'Authenticating…' : 'Authenticate', fn: '_gdTest()', kind: creds ? 'primary' : 'quiet', disabled: !creds || GD.testing },
      ],
    },
    {
      n: 2, title: 'Assess the tenant',
      state: assessed ? 'done' : (connected ? 'ready' : 'todo'),
      what: 'Runs 300+ automated checks against the tenant and produces a maturity score with a list of findings. Takes about 90 seconds. Read-only.',
      need: 'A successful Authenticate in step 1, then Scope assessment in the sidebar: the channels the customer owns, what to check (keep the default scopes for a DLP engagement), the frameworks, and the organisation and assessor names.',
      status: running ? 'Running… the progress card below shows each check as it completes.' : (assessed ? 'Assessment complete. Results are below.' : (connected ? 'Open Scope assessment in the sidebar, check what it covers, then click Run assessment there. The results appear on this page.' : 'Authenticate in step 1 first.')),
      actions: [{ label: running ? 'Running…' : 'Run assessment', fn: '_gdRun()', kind: 'primary', disabled: !connected || running }],
    },
    {
      n: 3, title: 'Read the results',
      state: assessed ? 'ready' : 'todo',
      what: 'The Summary card gives the score and what it counts. Detailed findings lists every check, grouped by section and filterable by status, with what it means and what to do; a 🔧 button marks the findings that have a one-click recipe. Regulatory alignment maps findings to frameworks the customer cares about.',
      need: 'Nothing. Walk the customer through the Action required findings first; they are the ones that expose data today.',
      status: assessed ? 'Scroll down to Summary, Scores by section and Detailed findings.' : 'Available after the assessment runs.',
      actions: [{ label: 'Jump to results', fn: '_gdGoResults()', kind: 'quiet', disabled: !assessed }],
    },
    {
      n: 4, title: 'Pick a policy pack and run the preflight',
      state: deployed ? 'done' : (assessed || (sameTenant && GD.conn && GD.conn.ok) ? 'ready' : 'todo'),
      what: 'A policy pack is a complete, layered policy design for one situation: Healthcare PHI, CUI markings, Zscaler\'s enterprise best practice, Endpoint DLP, and so on. Each card says who it is for and when to use it. Preflight reads the tenant and shows exactly what would be created, what already exists and is kept, and what the impact is. Nothing is written.',
      need: 'A connected tenant. Preflight works in read-only mode; it is the plan you show the customer.',
      status: deployed ? `Last deployment ${_gdE(deployed.status)} on ${_gdE(deployed.at)}: ${deployed.created || 0} created.` : 'Open Deploy policy packs, tick a policy pack, click Run preflight, then read the Impact cards and the plan.',
      actions: [{ label: 'Open Deploy policy packs', fn: 'openDlpPacksModal()', kind: 'primary' }],
    },
    {
      n: 5, title: 'Close the gap: deploy from here, or hand off as Terraform',
      state: deployed ? 'done' : (assessed || (sameTenant && GD.conn && GD.conn.ok) ? 'ready' : 'todo'),
      what: 'Two ways to create the missing objects. <strong>Deploy from here</strong>: enable write mode in Deploy policy packs, review, tick the consent box, deploy; every rule arrives disabled and nothing the customer already has is overwritten. <strong>Hand off as Terraform</strong>: for customers whose platform team manages Zscaler as code, download the same policy pack as a Terraform workspace; in gap mode it imports what exists so their first plan is exactly the gap.',
      need: 'Deploying from here needs write mode: a confirmation phrase, after which it stays on for this server (every browser using it) until the server restarts or you switch it back. The Terraform route needs nothing from this tool after the download; the platform team needs an API client with write access.',
      status: deployed ? 'Deployed and activated. Enable rules one by one in the ZIA portal, monitor first.' : 'Choose the route the customer prefers. Both start from the same preflight.',
      actions: [{ label: 'Deploy policy packs', fn: 'openDlpPacksModal()', kind: 'primary' }, { label: 'Terraform hand-off', fn: "openToolTab('terraform')", kind: 'quiet' }],
    },
    {
      n: 6, title: 'Move the tenant to Evaluate All Rules',
      state: assessed || (sameTenant && GD.conn && GD.conn.ok) ? 'ready' : 'todo',
      what: 'By default ZIA stops at the first matching DLP rule, so a broad monitor rule near the top silently shadows every block rule below it. Evaluate All Rules lets every matching rule fire and log its own incident, which is what a layered policy (monitor + block + caution) needs. The Inline DLP Rule migration wizard reads the current mode, reorders the rules so the switch is safe, and shows you the plan before anything changes.',
      need: 'Check 5.20 in the assessment says whether the tenant is already in Evaluate All Rules mode and whether the current order is safe to switch. The switch itself is made in the ZIA Admin Portal under Policy > Data Loss Prevention > Advanced Settings.',
      status: 'Open the Inline DLP Rule migration card below the results and follow its five steps.',
      actions: [{ label: 'Open Rule migration', fn: '_gdGoMigration()', kind: 'primary' }],
    },
    {
      n: 7, title: 'Come back and measure the journey',
      state: deployed ? 'ready' : 'todo',
      what: 'On the next visit, run the assessment again with the same tenant profile. The Data governance journey card places the tenant on the five-stage ladder (Foundation, Policies deployed, Visibility, Containment, Enforcement), names the exact rules to enable or harden next, and compares with the previous visit. Nothing the customer changed is reverted; an enabled rule or a hardened action is progress.',
      need: 'The tenant profile you saved in step 1, so the history lines up.',
      status: GD.profile ? 'Profile selected: the next assessment is recorded against it.' : 'Save a tenant profile in Tenant details (step 1) so history is kept.',
      actions: [{ label: 'Run assessment', fn: '_gdRun()', kind: 'primary', disabled: !creds }, { label: 'Journey card (Deploy policy packs)', fn: 'openDlpPacksModal()', kind: 'quiet' }],
    },
  ];
}
// Evaluate All Rules opens the migration wizard as a modal; the wizard is
// no longer an always-present section on the page.
function _gdGoMigration() {
  const m = document.getElementById('migrateModal');
  if (!m) { alert('The Inline DLP Rule migration wizard is not available on this page.'); return; }
  GD._migrateOpener = document.activeElement;   // focus goes back there on close
  m.style.display = 'block';
  document.body.style.overflow = 'hidden';
  // Expand any collapsed section inside the wizard so it opens ready to use.
  m.querySelectorAll('.card-toggle[aria-expanded="false"]').forEach(b => b.click());
  const h = document.getElementById('migrateModalTitle'); if (h && h.focus) h.focus();
}
function closeMigrateModal() {
  const m = document.getElementById('migrateModal');
  if (m) m.style.display = 'none';
  document.body.style.overflow = '';
  const o = GD._migrateOpener; GD._migrateOpener = null;
  if (o && document.body.contains(o) && typeof o.focus === 'function') o.focus();
}
window.closeMigrateModal = closeMigrateModal;
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    const m = document.getElementById('migrateModal');
    if (m && m.style.display !== 'none') closeMigrateModal();
  }
});

function _gdTlsNote(t) {
  if (!t) return '';
  if (t.ca_bundle && !t.ca_bundle_exists) return ` · <strong>CA bundle not found</strong>: REQUESTS_CA_BUNDLE points at <code>${_gdE(t.ca_bundle)}</code> but that file does not exist; connections will fail with a certificate error.`;
  if (t.ca_bundle) return ` · TLS inspection CA bundle: <code>${_gdE(t.ca_bundle)}</code>${t.local_settings_bat || t.local_settings_env ? ' (from local_settings)' : ''}.`;
  return ' · No corporate CA bundle configured. If Authenticate reports a certificate error, copy local_settings.bat.example to local_settings.bat and set REQUESTS_CA_BUNDLE; it survives updates.';
}


// ── Update the app from here ───────────────────────────────────────
// The server pulls main, installs requirements and restarts itself; the
// page waits for the new process and reloads.
function _gdWhereHtml() {
  const a = GD.about;
  if (!a || !a.app_dir) return '';
  let s = `Installed at <code>${_gdE(a.app_dir)}</code>${a.git_commit && a.git_commit !== 'unknown' ? ` · build ${_gdE(a.git_commit)}` : ''}`;
  // The Update button is always there on a git checkout: the update
  // itself reports what GitHub says, even when the quick check failed.
  const btn = (label, primary) => ` <button type="button" class="gd-btn ${primary ? 'primary' : 'quiet'} gd-btn-sm" id="gdUpdateBtn" onclick="_gdUpdateApp()">${label}</button>`;
  // Which branch Update app pulls. Stable (main) is what customers run;
  // QA and Development exist to try a fix before it is promoted. The list
  // comes from the server (an allowlist); the pick is kept across re-renders.
  const branches = Array.isArray(a.branches) && a.branches.length ? a.branches : [{ name: 'main', label: 'Stable (main)', current: true }];
  const chosen = GD.updBranch || (branches.find(b => b.current) || branches[0]).name;
  const sel = a.is_git_checkout === false ? '' : ` <label class="gd-upd-branch">Branch <select id="gdUpdBranch" onchange="GD.updBranch = this.value; _gdUpdateCheck()" title="Stable (main) is what customers run. QA and Development carry work that has not been through QA yet; use them to try a fix before it is promoted.">${branches.map(b => `<option value="${_gdE(b.name)}"${b.name === chosen ? ' selected' : ''}>${_gdE(b.label)}${b.current ? ' — installed' : ''}</option>`).join('')}</select></label>`;
  const where = a.branch ? `${_gdE(a.branch)} on GitHub` : 'GitHub';
  if (a.is_git_checkout === false) {
    s += ' · <strong>not a git checkout</strong>: it cannot be updated in place.' + btn('How to update', true);
  } else if (a.latest_commit && a.git_commit && a.git_commit !== 'unknown' && a.latest_commit !== a.git_commit) {
    s += ` · <strong>update available</strong> (${where} is on ${_gdE(a.latest_commit)})` + btn('Update app now', true);
  } else if (a.latest_commit) {
    s += ' · up to date' + btn('Update app', false) + ' <button type="button" class="gd-link" onclick="_gdUpdateCheck()">Check again</button>';
  } else {
    s += ` · <strong>could not check GitHub</strong>${a.latest_commit_error ? ` (${_gdE(a.latest_commit_error)})` : ''}` + btn('Update app', true) + ' <button type="button" class="gd-link" onclick="_gdUpdateCheck()">Check again</button>';
  }
  return s + sel + _gdTlsNote(a.tls);
}
function _gdUpdBranch() {
  const sel = document.getElementById('gdUpdBranch');
  return (sel && sel.value) || GD.updBranch || '';
}
function _gdUpdateBox(html, show = true) {
  const box = document.getElementById('gdUpdate');
  if (!box) return;
  box.hidden = !show; box.innerHTML = html;
}
async function _gdUpdateCheck() {
  _gdUpdateBox('<span class="gd-upd-line">Checking GitHub…</span>');
  try {
    const branch = _gdUpdBranch();
    const r = await fetch('/api/app/update/status?refresh=1' + (branch ? '&branch=' + encodeURIComponent(branch) : ''), { cache: 'no-store' });
    const st = await r.json();
    if (!r.ok) throw new Error(st.detail || `HTTP ${r.status}`);
    GD.updBranch = st.target_branch || branch || GD.updBranch;
    GD.about = Object.assign({}, GD.about, { git_commit: st.local_commit || GD.about.git_commit, latest_commit: st.remote_commit, latest_commit_error: st.remote_error || null,
                                             is_git_checkout: st.is_git_checkout, branch: st.branch || GD.about.branch, branches: st.branches || GD.about.branches });
    _gdRender();
    const target = st.target_branch || 'main';
    const here = `this install is on ${_gdE(st.local_commit)}${st.branch ? ` (${_gdE(st.branch)})` : ''}`;
    const note = st.reason && st.can_update ? `<div class="gd-upd-line soft">${_gdE(st.reason)}</div>` : '';
    if (st.reason && !st.can_update) _gdUpdateBox(`<span class="gd-upd-line warn">${_gdE(st.reason)}</span>`);
    else if (st.update_available) _gdUpdateBox(`<span class="gd-upd-line">${_gdE(target)} on GitHub is on build ${_gdE(st.remote_commit)}; ${here}.${st.branch && st.branch !== target ? ` Update app switches this install to ${_gdE(target)}.` : ''}</span>${note}`);
    else _gdUpdateBox(`<span class="gd-upd-line ok">Up to date with ${_gdE(target)} (build ${_gdE(st.local_commit || '?')}).</span>`);
  } catch (e) { _gdUpdateBox(`<span class="gd-upd-line warn">Could not check: ${_gdE(e.message)}</span>`); }
}
function _gdUpdateHelp() {
  // A ZIP copy has no .git folder. The way out depends on where the app
  // runs: a Windows path (C:\...) gets the Command Prompt one-liner that
  // clones and repoints the shortcuts; a Mac or Linux path gets the
  // Terminal lines. Either way the plain alternative (fresh ZIP, same
  // folder, installer again) is stated first, because it needs no git.
  const dir = (GD.about && GD.about.app_dir) || '';
  const win = /^[A-Za-z]:[\\/]|^\\\\/.test(dir);
  const settings = win ? 'local_settings.bat' : 'local_settings.env';
  const cmd = win
    ? 'cd /d "%USERPROFILE%" && (if exist "DLP-Check\\\\.git" (cd /d "%USERPROFILE%\\\\DLP-Check" && git fetch origin && git checkout main && git pull --ff-only origin main) else (git clone https://github.com/berserkerjay/DLP-Check.git && cd /d "%USERPROFILE%\\\\DLP-Check")) && call INSTALL_Zscaler_Assessment.bat && call UPDATE_Zscaler_Assessment.bat'
    : 'cd ~ && git clone https://github.com/berserkerjay/DLP-Check.git && cd DLP-Check && ./install.sh && ./start.sh';
  const where = win ? 'a Command Prompt' : 'Terminal';
  const does = win ? 'it clones the repository under your user folder, installs it and repoints the shortcuts' : 'it clones the repository into your home folder, installs it and starts it';
  _gdUpdateBox(`<div class="gd-upd-line">This copy was not installed with git (a ZIP download), so it cannot pull updates. The simple way: stop the app, download a fresh ZIP from GitHub, replace this folder keeping <code>${settings}</code>, and run the installer again. Or, once, run this in ${where}; ${does}, and Update app works from then on. Copy <code>${settings}</code> from the old folder afterwards.</div>
    <pre class="gd-upd-cmd" id="gdUpdCmd">${_gdE(cmd)}</pre>
    <button type="button" class="gd-btn quiet gd-btn-sm" onclick="navigator.clipboard && navigator.clipboard.writeText(document.getElementById('gdUpdCmd').textContent).then(() => announce('Command copied'))">Copy command</button>`);
}
async function _gdUpdateApp() {
  if (GD.about && GD.about.is_git_checkout === false) { _gdUpdateHelp(); return; }
  const btn = document.getElementById('gdUpdateBtn'); if (btn) { btn.disabled = true; btn.textContent = 'Updating…'; }
  const lines = [];
  const show = (extra = '') => _gdUpdateBox(`<div class="gd-upd-steps">${lines.map(l => `<div class="gd-upd-line ${l.ok === false ? (l.soft ? 'soft' : 'warn') : l.ok ? 'ok' : ''}">${l.ok === false ? (l.soft ? '⚠' : '✗') : l.ok ? '✓' : '…'} ${_gdE(l.name)}${l.detail ? ` <span class="dim">— ${_gdE(l.detail)}</span>` : ''}</div>`).join('')}${extra}</div>`);
  const branch = _gdUpdBranch() || null;
  lines.push({ name: branch ? `Pulling the latest ${branch} from GitHub` : 'Pulling the latest code from GitHub', ok: null }); show();
  let res;
  try {
    const r = await fetch('/api/app/update', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ branch }) });
    res = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(res.detail || `HTTP ${r.status}`);
  } catch (e) {
    lines.length = 0; lines.push({ name: 'Update failed', ok: false, detail: e.message }); show();
    if (btn) { btn.disabled = false; btn.textContent = 'Update app'; }
    return;
  }
  lines.length = 0;
  for (const s of res.steps || []) lines.push({ name: s.name, ok: s.ok, detail: s.detail, soft: !!s.soft });
  if (!res.ok) { show(); if (btn) { btn.disabled = false; btn.textContent = 'Update app'; } return; }
  if (!res.updated) { show('<div class="gd-upd-line ok">Already on the latest build.</div>'); if (btn) { btn.disabled = false; btn.textContent = 'Update app'; } _gdUpdateCheck(); return; }
  lines.push({ name: `Restarting the app on build ${res.after}`, ok: null }); show();
  let hint = 'Close the app with STOP_Zscaler_Assessment.bat and open it again from the shortcut.';
  try {
    const r = await fetch('/api/app/restart', { method: 'POST' });
    const rs = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(rs.detail || `HTTP ${r.status}`);
    if (rs.hint) hint = rs.hint;
    if (!rs.scheduled) throw new Error(rs.error || 'the relauncher could not be started');
  } catch (e) {
    lines[lines.length - 1] = { name: 'Restart could not be scheduled', ok: false, detail: e.message + '. The update itself succeeded. ' + hint }; show(); return;
  }
  // Wait for the new process: health answers with the new build.
  const started = Date.now();
  const poll = async () => {
    try {
      const h = await (await fetch('/api/health', { cache: 'no-store' })).json();
      if (h.git_commit && h.git_commit === res.after) { lines[lines.length - 1] = { name: `Restarted on build ${h.git_commit}. Reloading…`, ok: true }; show(); setTimeout(() => location.reload(), 600); return; }
    } catch (_) { /* server is down while it restarts */ }
    if (Date.now() - started > 90000) { lines[lines.length - 1] = { name: 'The app did not come back within 90 seconds', ok: false, detail: 'The update itself succeeded. ' + hint }; show(); return; }
    setTimeout(poll, 1500);
  };
  setTimeout(poll, 2500);
}

// ── Rendering ──────────────────────────────────────────────────────
function _gdRender() {
  _gdAuthStatus();
  const host = document.getElementById('gdPanel');
  if (!host) return;
  const steps = _gdSteps();
  const doneCount = steps.filter(s => s.state === 'done').length;
  const creds1 = steps[0].state !== 'todo';
  if (GD.tenantOpen == null) GD.tenantOpen = !creds1;
  const html = `
    <div class="gd-head">
      <div>
        <div class="gd-eyebrow">Start here</div>
        <h2 class="gd-title">Seven steps from "unknown tenant" to "governed data"</h2>
        <p class="gd-sub">Follow the steps in order. Each one explains what it does, what you need, and what to click. Nothing is written to the customer's tenant until step 5, and only after you approve a plan or hand it off as Terraform.</p>
        <p class="gd-sub gd-where" id="gdWhere">${_gdWhereHtml()}</p>
        <div id="gdUpdate" class="gd-update" hidden></div>
      </div>
      <div class="gd-controls">
        <label class="gd-switch" title="Guided mode keeps the seven steps in focus: it hides the Compliance coverage card and the Reference tools (Best practices, Zscaler update check). The gap-finding and deploy tools stay in the toolbar.">
          <input type="checkbox" ${GD.mode === 'guided' ? 'checked' : ''} onchange="_gdSetMode(this.checked ? 'guided' : 'advanced')" aria-label="Guided mode">
          <span class="track"><span class="knob"></span></span><span class="lbl">Guided mode</span>
        </label>
        <button type="button" class="gd-btn quiet" onclick="_gdHelp(true)">? Help &amp; glossary</button>
      </div>
    </div>
    <div class="gd-progress" role="progressbar" aria-label="Steps done" aria-valuemin="0" aria-valuemax="${steps.length}" aria-valuenow="${doneCount}" aria-valuetext="${doneCount} of ${steps.length} steps done"><div class="bar" style="width:${(doneCount / steps.length) * 100}%"></div></div>
    <ol class="gd-steps">
      ${steps.map(s => `
      <li class="gd-step is-${s.state}">
        <div class="gd-step-n"><span aria-hidden="true">${s.n}</span></div>
        <div class="gd-step-body">
          <div class="gd-step-top"><h3><span class="gd-step-label">Step ${s.n} of ${steps.length}</span> ${_gdE(s.title)}</h3><span class="gd-chip ${s.state}">${{ done: 'Done ✓', ready: 'Ready', todo: 'Not yet' }[s.state]}</span></div>
          <p class="gd-what">${s.what}</p>
          <p class="gd-need"><strong>You need:</strong> ${s.need}</p>
          <div class="gd-status">${s.status}</div>
          ${s.n === 1 ? _gdConnHtml() : ''}
          <div class="gd-actions">${s.actions.map(a => `<button type="button" class="gd-btn ${a.kind}" ${a.disabled ? 'disabled' : ''} onclick="${a.fn}">${_gdE(a.label)}</button>`).join('')}</div>
          ${s.tenant ? `<details class="gd-tenant" id="gdTenantDetails" ${GD.tenantOpen ? 'open' : ''}><summary>Tenant details <span class="gd-dim">${creds1 ? '· entered; expand to change or to save a profile' : '· cloud, vanity domain, API client (sign-in only)'}</span></summary><div id="gdTenantSlot"></div></details>` : ''}
        </div>
      </li>`).join('')}
    </ol>`;
  // The tenant configuration card is a live form (the operator may be
  // typing in it), so it is never re-created: it is parked while the
  // panel's HTML is replaced and moved back into step 1 afterwards, and
  // the panel is only re-rendered when something actually changed.
  const card = document.getElementById('configCard');
  const park = document.getElementById('configPark');
  const slotNow = document.getElementById('gdTenantSlot');
  if (html === GD._lastHtml && card && slotNow && card.parentNode === slotNow) return;
  const active = document.activeElement, sel = active && active.value != null && typeof active.selectionStart === 'number' ? [active.selectionStart, active.selectionEnd] : null;
  if (card && park && card.parentNode !== park) park.appendChild(card);
  host.innerHTML = html;
  GD._lastHtml = html;
  const slot = document.getElementById('gdTenantSlot');
  if (card && slot) slot.appendChild(card);
  const det = document.getElementById('gdTenantDetails');
  if (det) det.addEventListener('toggle', () => { GD.tenantOpen = det.open; });
  if (active && active.id && document.getElementById(active.id) && document.activeElement !== active) {
    const el = document.getElementById(active.id);
    try { el.focus({ preventScroll: true }); if (sel) el.setSelectionRange(sel[0], sel[1]); } catch (e) { /* not a text field */ }
  }
}

// The identity a connection result belongs to: the vanity domain for a
// ZIdentity API client, the admin username for the classic sign-in — the
// same key _gdSteps uses, so the status never goes blank on the classic sign-in.
function _gdIdent() {
  const legacy = (document.getElementById('authMethod') || {}).value === 'legacy';
  return legacy ? _gdVal('zuser') : _gdVal('vd');
}
function _gdAuthStatus() {
  const st = document.getElementById('authStatus');
  if (!st) return;
  const c = GD.conn;
  if (GD.testing) { st.textContent = 'Authenticating…'; st.className = 'auth-status'; return; }
  if (!c || c.vd !== _gdIdent()) { st.textContent = ''; st.className = 'auth-status'; return; }
  st.className = 'auth-status ' + (c.ok ? 'ok' : 'bad');
  st.textContent = c.ok ? `Connected to ${c.label}. Now run the assessment from Start here, step 2.` : `Could not connect: ${c.cause || 'see Start here, step 1'}`;
}
function _gdConnHtml() {
  const c = GD.conn;
  if (!c || c.vd !== _gdIdent()) return '';
  if (c.ok) {
    return `<div class="gd-conn ok"><strong>Connected.</strong> ${_gdE(c.label)} · ${c.dictionaries} dictionaries (${c.custom_dictionaries} custom) · ${c.engines} engines · ${c.web_rules} web DLP rules${(c.problems || []).length ? `<div class="gd-warn">${c.problems.map(p => _gdE(p)).join('<br>')}</div>` : ''}</div>`;
  }
  return `<div class="gd-conn bad"><strong>Could not connect.</strong> ${_gdE(c.cause || '')}<div class="gd-fix"><strong>What to do:</strong> ${_gdE(c.fix || '')}</div>${c.raw ? `<details><summary>Technical detail</summary><code>${_gdE(c.raw)}</code></details>` : ''}</div>`;
}

// ── Actions ────────────────────────────────────────────────────────
function _gdGoConfig() {
  GD.tenantOpen = true;
  const det = document.getElementById('gdTenantDetails');
  if (det) det.open = true;
  const card = document.getElementById('configCard');
  if (card) {
    const h = card.querySelector('h2.collapsible');
    if (card.classList.contains('collapsed') && h) h.click();
    card.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  const first = ['vd', 'cid', 'csec'].map(id => document.getElementById(id)).find(el => el && !el.value);
  if (first) setTimeout(() => first.focus(), 400);
}
function _gdGoResults() {
  const r = document.getElementById('results');
  if (r) r.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
function _gdRun() {
  const btn = document.getElementById('runBtn');
  if (btn && btn.disabled) { if (typeof announce === 'function') announce('The assessment is already running; the progress card shows each check as it completes.'); return; }
  // One behaviour for every "Run assessment" button: the run happens on
  // this page (sign-in first when needed, via the sidebar's runner) and
  // the results land below. "Open in new tab" on the results is the
  // explicit way to mirror them into their own tab.
  if (typeof window.__dbRunFromSidebar === 'function') window.__dbRunFromSidebar();
  else if (typeof runAssessment === 'function') runAssessment(); else if (btn) btn.click();
  _gdRender();
}
// Which sign-in failed, in the caller's words. Four different things used
// to read as "the tool's own server did not answer": this app's own UI
// token missing (a 401 the fetch wrapper could not clear), the browser
// being unable to show a dialog, the server really being unreachable, and
// the tenant refusing the credentials. Each gets its own cause and fix.
function _gdConnFailure(kind, extra) {
  const K = {
    token: { kind: 'local', cause: 'This app\'s own sign-in is missing: the UI token was not entered, so the request never reached Zscaler.',
             fix: 'Open the app from its launcher, or paste the token from ui_token.txt (next to the app) into the unlock box, then click Authenticate again. This is not about the tenant credentials.' },
    dialog: { kind: 'browser', cause: 'This browser could not show the sign-in dialog, so the request never reached Zscaler.',
              fix: 'Open the app in Chrome, Edge or Firefox from its launcher (the launcher carries the token), then click Authenticate again.' },
    server: { kind: 'transport', cause: 'The tool\'s own server did not answer.',
              fix: 'Make sure the server window is still open (the launcher, ./start.sh or docker compose), then try again.' },
  }[kind];
  return Object.assign({ ok: false }, K, extra || {});
}
async function _gdTest() {
  if (typeof migrateCredBody !== 'function') return;
  if (GD.testing) return;   // one check at a time: a second click while one is running is ignored
  const body = migrateCredBody(); delete body.customer_id;
  const ident = body.auth_method === 'legacy' ? body.username : body.vanity_domain;   // what "same tenant" is compared on
  GD.testing = true; _gdRender();
  const formBtn = document.getElementById('authBtn'); if (formBtn) { formBtn.disabled = true; formBtn.setAttribute('aria-busy', 'true'); }
  if (window.__dlpAskAgain) window.__dlpAskAgain();   // a deliberate click may ask for this app's own token again
  try {
    const r = await fetch('/api/tenant/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await r.json().catch(() => ({}));
    if (r.status === 401 && data && data.token_required) {
      // The fetch wrapper marks a 401 it could not clear because the browser
      // could not ask for the token at all (no dialog, prompt() unsupported).
      GD.conn = r.dlpDialogUnavailable
        ? _gdConnFailure('dialog', { vd: ident, raw: String(r.dlpDialogUnavailable) })
        : _gdConnFailure('token', { vd: ident, raw: String(data.detail || 'HTTP 401 token_required') });
    } else if (!r.ok) {
      const d = (data && typeof data.detail === 'object') ? data.detail : { cause: 'The connection failed.', fix: 'Re-check the tenant details and try again.', raw: String(data.detail || `HTTP ${r.status}`) };
      GD.conn = { ok: false, kind: r.status === 403 ? 'permission' : 'tenant', vd: ident, label: d.tenant_label, cause: d.cause, fix: d.fix, raw: d.raw, status: r.status };
    } else {
      GD.conn = { ok: true, vd: ident, label: data.tenant_label, dictionaries: data.dictionaries, custom_dictionaries: data.custom_dictionaries,
                  engines: data.engines, web_rules: data.web_rules, problems: data.problems || [], at: new Date().toISOString() };
    }
  } catch (e) {
    const msg = String(e && e.message || e);
    GD.conn = /prompt|dialog|not supported|showModal/i.test(msg)
      ? _gdConnFailure('dialog', { vd: ident, raw: msg })
      : _gdConnFailure('server', { vd: ident, raw: msg });
  } finally {
    GD.testing = false; _gdSave(); _gdRender();
    if (formBtn) { formBtn.disabled = false; formBtn.removeAttribute('aria-busy'); }
    _gdAuthVerdict(GD.conn);
  }
}
// The verdict the moment Authenticate finishes. Success stays inline: the
// step-1 card turns green, the result is announced, and the next action
// (Run assessment) is the obvious button — no dialog to dismiss. A
// failure opens the app's own accessible dialog with the cause, what to
// do, and the technical detail behind a disclosure (never a secret).
function _gdAuthVerdict(conn) {
  if (!conn) return;
  if (conn.ok) {
    if (typeof announce === 'function') announce(`Connected to ${conn.label || conn.vd || 'the tenant'}. Next: run the assessment from Start here, step 2.`);
    const card = document.querySelector('.gd-conn.ok');
    if (card) { card.setAttribute('tabindex', '-1'); try { card.focus({ preventScroll: false }); } catch (e) {} }
    return;
  }
  const title = conn.kind === 'local' ? 'This app needs its own sign-in first'
    : conn.kind === 'browser' ? 'This browser could not show the sign-in dialog'
    : conn.kind === 'transport' ? 'The app\'s server did not answer'
    : conn.kind === 'permission' ? `Signed in, but not allowed to read ${conn.label || 'this tenant'}`
    : `Could not connect to ${conn.label || conn.vd || 'the tenant'}`;
  if (typeof announce === 'function') announce(`${title}. ${conn.cause || ''}`);
  if (window.dlpDialog && window.dlpDialog.notice) {
    window.dlpDialog.notice({ title, body: conn.cause || 'The connection failed.', fix: conn.fix || 'Re-check the tenant details and try again.',
                              detail: conn.raw ? String(conn.raw).slice(0, 600) : '', tone: 'bad', okLabel: 'Back to the form' });
  }
}
// Kept for callers that still name it.
function _gdAuthPopup(conn) { return _gdAuthVerdict(conn); }
function _gdSetMode(mode) {
  GD.mode = mode; _gdSave(); _gdApplyMode(); _gdRender();
  try { if (typeof announce === 'function') announce(mode === 'guided' ? 'Guided mode on: the Compliance coverage card is folded away; every tool stays in the toolbar.' : 'Guided mode off: everything shown.'); } catch (e) { /* ignore */ }
  const panel = document.getElementById('gdPanel') || document.querySelector('.gd-panel');
  if (panel && panel.scrollIntoView) panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Guided mode hides the advanced tools. Cards are found by their heading
// text so index.html needs no markup changes.
const GD_ADVANCED_HEADINGS = ['Compliance coverage'];
// Guided mode keeps the seven steps in focus by hiding the Compliance
// Coverage card. Every tool stays in the toolbar in both modes: a tool a
// first-week engineer cannot see is a tool they cannot click, and the
// Reference group holds Advanced settings, Best practices, Zscaler
// Updates and the Evaluate All Rules reference.
const GD_ADVANCED_TOOLGROUPS = [];
function _gdApplyMode() {
  document.body.classList.toggle('gd-guided', GD.mode === 'guided');
  document.querySelectorAll('div.card').forEach(card => {
    const h = card.querySelector(':scope > h2, :scope > h3, :scope > div h2');
    const t = (h ? h.textContent : '').trim();
    if (GD_ADVANCED_HEADINGS.some(x => t.startsWith(x))) card.classList.add('gd-advanced');
  });
  GD_ADVANCED_TOOLGROUPS.forEach(label => {
    document.querySelectorAll(`.tool-group[aria-label="${label}"]`).forEach(g => g.classList.add('gd-advanced'));
  });
}

// ── Help drawer ────────────────────────────────────────────────────
// The glossary lives in explain.js (shared with /help); this fallback covers a page served without it.
const GD_GLOSSARY = window.DLP_GLOSSARY || [['Dictionary', 'The thing to look for: phrases and patterns.'], ['Engine', 'How dictionaries combine into a decision.'], ['Rule (policy)', 'Where and how an engine is enforced.']];
function _gdHelp(open) {
  GD.helpOpen = open;
  let d = document.getElementById('gdHelp');
  if (!d) {
    d = document.createElement('div'); d.id = 'gdHelp'; d.setAttribute('role', 'dialog'); d.setAttribute('aria-label', 'Help and glossary');
    document.body.appendChild(d);
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && GD.helpOpen) _gdHelp(false); });
  }
  d.classList.toggle('is-open', open);
  if (!open) return;
  d.innerHTML = `
    <div class="gd-help-sheet">
      <header><h2>How this tool works</h2><button type="button" class="gd-btn quiet" onclick="_gdHelp(false)" aria-label="Close help">✕</button></header>
      <p>DLP-Check does two things. First it <strong>assesses</strong> a Zscaler tenant against a checklist of best practices and gives it a score. Then it <strong>closes the gaps</strong> by deploying policy packs: ready-made DLP and containment configuration that is checked against the tenant and approved by you before anything is written, into an empty tenant or on top of what is already there. Afterwards it <strong>measures the journey</strong>: how far the tenant has taken that policy pack, from deployed to monitoring to enforcing, and what to enable next.</p>
      <p>A good first engagement: connect, run the assessment, walk the customer through the critical findings, then run a preflight for the pack that matches their regulation and show them the plan. Deploy only when the customer has agreed and the server is running with writes enabled.</p>
      <h3>Tools at a glance</h3>
      <dl>
        <dt>Assessment (Run Assessment)</dt><dd>300+ read-only checks against the tenant, a score, findings with fixes, and the Data governance journey card for every policy pack.</dd>
        <dt>Tenant profiles</dt><dd>One saved record per customer (details, scopes, applicable policy packs, optional remembered secret) with the history of every assessment.</dd>
        <dt>Deploy policy packs</dt><dd>Pick a policy pack, choose which DLP channels its engines go into (Inline Web, Endpoint DLP, SaaS Security, Outbound Email: a ticked channel the pack has no rule for gets a monitor-only rule with the pack's engines, an unticked one is skipped), preflight against the tenant, review the exact plan, enable write mode, approve, deploy. Every rule arrives disabled; existing objects are kept. <em>Where is this tenant?</em> on a policy pack card measures the journey. Every deployment is recorded under <em>Previous deployments</em>, where <em>Undo</em> deletes exactly what it created.</dd>
        <dt>Terraform hand-off</dt><dd>The same policy pack as a Terraform workspace for the official zscaler/zia provider, for platform teams that manage Zscaler as code. Gap mode imports what already exists so the first plan is exactly the gap. The repository also carries a validated workspace per pack under terraform/.</dd>
        <dt>Evaluate All Rules (Inline DLP Rule migration)</dt><dd>Reorders web DLP rules so the tenant can switch from first-match-wins to Evaluate All Rules safely; check 5.20 in the assessment says whether it is needed.</dd>
        <dt>Bypass / non-inspected</dt><dd>Every SSL bypass, allow rule and Client Connector exemption that lets traffic skip inspection, with exports. Opens in its own tab.</dd>
        <dt>SSL inspection flow</dt><dd>Live flow diagram: for each DLP-relevant traffic class (file sharing, webmail, AI, social, uncategorised sites…) which SSL rule decides, whether it is decrypted, and whether inline Web DLP can see it. Gaps are highlighted with the fix. Refresh or auto-refresh from the tab.</dd>
        <dt>DLP efficacy</dt><dd>Scores every custom dictionary and engine for false-positive risk and lets you test sample text against them.</dd>
        <dt>Best practices</dt><dd>Curated Zscaler best-practice articles rated by source credibility. <em>Update library now</em> reads the sitemaps of help.zscaler.com, the Zscaler blog and the developer portal (and walks the partner sites), adds every new best-practice or leading-practice article, and shows per source whether it answered and why not. New finds are kept across restarts; a background refresh runs every 6 hours.</dd>
        <dt>Zscaler updates</dt><dd>A check of PyPI and help.zscaler.com for SDK and documentation changes since last time.</dd>
        <dt>Log analyzer</dt><dd>Drop in the ZIP from Client Connector's Export Logs, single .log files or a PAC file. Analysed on this computer, nothing stored. Tells you what happened, what it means for the user and what to do next.</dd>
        <dt>Packs from a design file (command line)</dt><dd><code>python tools/pack_from_design.py &lt;pack&gt;</code> turns a DLP engineer's dictionary/engine design into a pack, enforcing ZIA's documented limits.</dd>
      </dl>
      <h3>Glossary</h3>
      <dl>${GD_GLOSSARY.map(([t, d2]) => `<dt>${_gdE(t)}</dt><dd>${_gdE(d2)}</dd>`).join('')}</dl>
      <h3>If something goes wrong</h3>
      <ul>${(window.DLP_TROUBLE || []).map(([t, d2]) => `<li><strong>${_gdE(t)}</strong>: ${_gdE(d2)}</li>`).join('')}</ul>
      <p class="gd-dim"><a href="/help" target="_blank" rel="noopener">What does everything do?</a> explains every function in plain English. Full walkthrough: GETTING_STARTED.md in the project folder.</p>
    </div>`;
  d.querySelector('.gd-help-sheet').focus?.();
}

// ── Journey card on the assessment results ─────────────────────────
// The assessment measures the tenant against every policy pack; this
// renders that as a card above the compliance section.
function _gdJourneyCard(j) {
  let card = document.getElementById('gdJourney');
  const anchor = document.getElementById('complianceCard') || document.getElementById('sectionGrid');
  if (!card) {
    if (!anchor) return;
    card = document.createElement('section'); card.id = 'gdJourney'; card.className = 'card gd-journey';
    card.setAttribute('aria-label', 'Data governance journey');
    (document.getElementById('complianceCard') ? anchor : anchor.closest('.card') || anchor).insertAdjacentElement(document.getElementById('complianceCard') ? 'beforebegin' : 'afterend', card);
  }
  if (!j) { card.hidden = true; return; }
  card.hidden = false;
  const E = _gdE;
  if (j.status === 'error') {
    card.innerHTML = `<h2>Data governance journey</h2><p class="gd-sub">Could not measure the tenant against the policy packs: ${E(j.error || 'unknown error')}. The assessment itself is complete.</p>`;
    return;
  }
  if (j.status === 'pending') {
    card.innerHTML = `<h2>Data governance journey</h2><p class="gd-sub"><span class="gd-spin" aria-hidden="true"></span> Measuring the tenant against each policy pack${j.current ? ` — ${E(j.current.replace(/^Data governance journey: /, ''))}` : ''}. The results above are final; this card fills in when the measurement finishes.</p>`;
    return;
  }
  const stages = (j.stages || []).map(s => `<li><b>${E(s.name)}</b> — ${E(s.what)}</li>`).join('');
  const rows = (j.baselines || []).map(b => `<div class="dz-journey ${b.state === 'governed' ? 'ok' : (b.state === 'blocked' ? 'fail' : (b.state === 'not_started' ? 'info' : 'warn'))}"><h3>${E(b.name)}${b.version ? ` <span class="gd-dim">v${E(b.version)}</span>` : ''}</h3>${typeof _dzJourneyRowHtml === 'function' ? _dzJourneyRowHtml(b, { max: 6 }) : `Stage ${b.stage} of 5 (${E(b.stage_name)})`}</div>`).join('');
  const overall = { not_started: 'Not started: none of the policy packs has been deployed yet.', in_progress: 'In progress: policy packs are deployed but not yet fully enabled and enforcing.', governed: 'Governed: every policy pack is deployed, enabled and enforcing.', blocked: 'Blocked: something a policy pack needs is missing from the tenant.' }[j.status] || j.status;
  const hist = ((GD.lastReport || {}).profile || {}).history || [];
  const prev = hist.length >= 2 ? hist[hist.length - 2] : null;
  let trend = '';
  if (prev && prev.journey) {
    const d = (j.stage || 0) - (prev.journey.stage || 0), ds = (j.score || 0) - (prev.journey.score || 0);
    trend = `<div class="gd-journey-mode">Since the previous assessment on ${E(new Date(prev.at).toLocaleDateString())}: stage ${prev.journey.stage || 0} → ${j.stage || 0} (${d > 0 ? '+' + d : d}), journey score ${prev.journey.score || 0}% → ${j.score || 0}% (${ds > 0 ? '+' + ds : ds}), assessment score ${prev.score ?? '?'}% → ${(GD.lastReport || {}).score ?? '?'}%.</div>`;
  } else if (GD.profile && hist.length === 1) {
    trend = `<div class="gd-journey-mode">First recorded assessment for this tenant profile. The next run will show the movement.</div>`;
  }
  card.innerHTML = `
    <h2>Data governance journey</h2>
    <p class="gd-sub">Where this tenant stands against each policy pack, measured read-only during the assessment. <strong>${E(overall)}</strong> Overall stage ${j.stage || 0} of 5, ${j.score || 0}% of the way. Deploying a policy pack (Deploy Studio) creates what is missing and keeps everything the customer already has; enabling and hardening rules in the ZIA portal moves the tenant up the ladder.</p>
    ${trend}
    <details class="dz-fold"><summary>The five stages</summary><ol class="dz-next">${stages}</ol></details>
    ${rows || '<p class="gd-sub">No policy packs are installed.</p>'}`;
}
(function () {
  const orig = window.showResults;
  if (typeof orig !== 'function') return;
  window.showResults = function (data) {
    orig.apply(this, arguments);
    GD.lastReport = data || null;
    try { _gdJourneyCard(data && data.journey); } catch (e) { console.warn('journey card', e); }
    try { if (data && data.profile) { _gdProfilesLoad(); } } catch (e) { /* ignore */ }
  };
})();

// ── Tenant profiles ─────────────────────────────────────────────────
// One saved record per customer tenant (server-side, git-ignored file):
// details, scopes, applicable policy packs, optional remembered secret, and
// the history of every assessment run against it.
const GD_INDUSTRIES = ['Healthcare', 'Federal', 'State & local government', 'Law enforcement (CJIS)', 'Financial services', 'Education', 'Manufacturing', 'Technology', 'Other'];
function _gdProfileSel() { return (GD.profiles || []).find(p => p.id === GD.profile) || null; }
async function _gdProfilesLoad() {
  try {
    const r = await fetch('/api/tenant-profiles', { cache: 'no-store' });
    const data = await r.json();
    GD.profiles = data.profiles || [];
    if (!GD.packs.length) {
      const pr = await fetch('/api/dlp-packs', { cache: 'no-store' }).then(x => x.json()).catch(() => ({}));
      // Every installed pack, the baselines first: an industry's packs (the Fed and CJIS packs among them) must be tickable here.
      GD.packs = [...(pr.packs || [])].sort((a, b) => (a.baseline ? 0 : 1) - (b.baseline ? 0 : 1));
    }
    const sel = _gdProfileSel();
    GD.profileHasSecret = !!(sel && sel.has_secret);
    if (GD.profile && sel) {
      const d = await fetch(`/api/tenant-profiles/${encodeURIComponent(GD.profile)}`, { cache: 'no-store' }).then(x => x.json()).catch(() => null);
      GD.profileDetail = d;
    } else { GD.profileDetail = null; if (!sel) GD.profile = ''; }
  } catch (e) { GD.profiles = GD.profiles || []; }
  _gdProfilesRender();
}
// The cloud value a saved profile carries, as the picker spells it today
// (older profiles stored gov / govus / beta / zspreview; see zscaler_clouds.py).
function _gdCloudValue(cloud) {
  const c = String(cloud || 'production').trim().toLowerCase().replace(/^admin\./, '').replace(/\.net$/, '');
  const alias = { '': 'production', prod: 'production', commercial: 'production', beta: 'zscalerbeta', zspreview: 'zscalerbeta', preview: 'zscalerbeta',
    gov: 'zscalergov', fedramp: 'zscalergov', govus: 'zscalergovus', 'zscalergov.us': 'zscalergovus', ten: 'zscalerten' };
  const v = alias[c] || c;
  const sel = document.getElementById('cloud');
  return sel && [...sel.options].some(o => o.value === v) ? v : 'production';
}

function _gdProfileFill(p) {
  const set = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.value = v; };
  set('org', p.org_name || ''); set('assessor', p.assessor || ''); set('cloud', _gdCloudValue(p.cloud));
  set('vd', p.vanity_domain || ''); set('cid', p.client_id || ''); set('custid', p.customer_id || '');
  set('csec', '');
  // The sign-in method and the classic API's username; its password and key are never sent back.
  set('authMethod', p.auth_method === 'legacy' ? 'legacy' : 'oneapi'); set('zuser', p.username || ''); set('zpass', ''); set('zkey', '');
  if (typeof applyAuthMethod === 'function') applyAuthMethod();
  if (Array.isArray(p.scopes) && p.scopes.length && typeof setSelectedScopes === 'function') setSelectedScopes(p.scopes);
  if (Array.isArray(p.frameworks) && p.frameworks.length) document.querySelectorAll('.fw-cb').forEach(cb => { cb.checked = p.frameworks.includes(cb.value); });
  // The profile's channel ownership (Scope page) replaces this browser's copy.
  if (p.channels && typeof p.channels === 'object' && Object.keys(p.channels).length && typeof window.__dbChannelsSet === 'function') window.__dbChannelsSet(p.channels);
  _gdApplyScope(p);
}
// The profile's industry decides what the assessment suggests: the
// frameworks it reports on (ticked here unless the profile saved its own
// choice) and the packs the journey is measured against and Deploy Policy
// Packs offers first. Everything else stays reachable, folded away.
async function _gdApplyScope(p) {
  GD.scope = null;
  if (!p || !p.industry) { _gdScopeNote(); return; }
  try {
    const r = await fetch(`/api/vertical-scope?profile_id=${encodeURIComponent(p.id || '')}&industry=${encodeURIComponent(p.industry)}`, { cache: 'no-store' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    GD.scope = await r.json();
    if (GD.scope.scoped && !(Array.isArray(p.frameworks) && p.frameworks.length)) {
      document.querySelectorAll('.fw-cb').forEach(cb => { cb.checked = GD.scope.frameworks.includes(cb.value); });
    }
  } catch (e) { GD.scope = null; }
  _gdScopeNote();
  _gdStudioFollowScope();
}
// Choosing an industry on the profile form: the industry's packs are ticked
// on the form at once (the operator adds or drops packs from there) and the
// scope follows, so Deploy policy packs pre-selects them without a save.
async function _gdIndustryChanged(industry) {
  const p = Object.assign({}, GD.profileDetail || {}, { id: GD.profile || '', industry: industry || '' });
  if (!industry) { GD.scope = null; _gdScopeNote(); _gdStudioFollowScope(); return; }
  try {
    const r = await fetch(`/api/vertical-scope?industry=${encodeURIComponent(industry)}`, { cache: 'no-store' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const sc = await r.json();
    // The industry's packs replace what was ticked for the previous industry; more can be ticked afterwards.
    document.querySelectorAll('.gd-prof-pack').forEach(cb => { cb.checked = sc.scoped && sc.packs.includes(cb.value); });
    GD.scope = sc;
    if (sc.scoped && !(Array.isArray(p.frameworks) && p.frameworks.length)) {
      document.querySelectorAll('.fw-cb').forEach(cb => { cb.checked = sc.frameworks.includes(cb.value); });
    }
  } catch (e) { GD.scope = null; }
  _gdScopeNote();
  _gdStudioFollowScope();
}
// Ticking or unticking a pack on the profile form narrows or widens the scope's packs right away.
function _gdProfPacksChanged() {
  const ticked = Array.from(document.querySelectorAll('.gd-prof-pack:checked')).map(x => x.value);
  if (GD.scope && GD.scope.scoped) {
    const names = {};
    (GD.packs || []).forEach(p => { names[p.id] = p.name || p.id; });
    const industryPacks = (GD.scope.industry_packs || GD.scope.packs || []);
    GD.scope.packs = ticked.length ? ticked : industryPacks;
    GD.scope.pack_names = GD.scope.packs.map(id => names[id] || id);
    GD.scope.packs_from = ticked.length ? 'profile' : 'industry';
  }
  _gdScopeNote();
  _gdStudioFollowScope();
}
function _gdStudioFollowScope() {
  if (typeof _dzAutoSelectFromScope === 'function') { try { _dzAutoSelectFromScope(); } catch (e) { /* studio not loaded */ } }
  if (typeof _dzRenderSelect === 'function' && document.getElementById('dzBody')) { try { _dzRenderSelect(); } catch (e) { /* studio closed */ } }
}
function _gdScopeNote() {
  const host = document.getElementById('gdScopeNote');
  if (!host) return;
  const sc = GD.scope;
  if (!sc || !sc.scoped) { host.hidden = true; host.innerHTML = ''; return; }
  host.hidden = false;
  host.innerHTML = `<strong>Scope: ${_gdE(sc.industry)}.</strong> ${_gdE(sc.reason)} Frameworks reported: ${_gdE(sc.frameworks.join(', '))}. Packs measured and offered first: ${_gdE((sc.pack_names || sc.packs).join(', '))}${sc.packs_from === 'profile' ? ' (ticked on the profile)' : ' (the industry\'s packs; tick packs on the profile to override)'}. Other frameworks and packs stay available under "show all".`;
}
async function _gdProfileSelect(id) {
  GD.profile = id || ''; _gdSave();
  await _gdProfilesLoad();
  const p = GD.profileDetail;
  if (p) { _gdProfileFill(p); if (typeof setStatus === 'function') setStatus(`Profile "${p.name}" loaded${p.has_secret ? ' (secret remembered on this laptop)' : (p.auth_method === 'legacy' ? ' — paste the admin password and the API key' : ' — paste the client secret')}.`, 'success'); }
  _gdRender();
}
function _gdProfileFormValues() {
  const sel = _gdProfileSel() || {};
  const q = id => document.getElementById(id);
  return {
    id: GD.profile || '',
    name: (q('gdProfName') || {}).value || sel.name || _gdVal('org') || _gdVal('vd'),
    org_name: _gdVal('org'), assessor: _gdVal('assessor'), cloud: _gdVal('cloud') || 'production',
    vanity_domain: _gdVal('vd'), client_id: _gdVal('cid'), client_secret: _gdVal('csec'),
    auth_method: typeof currentAuthMethod === 'function' ? currentAuthMethod() : 'oneapi',
    username: _gdVal('zuser'), password: _gdVal('zpass'), api_key: _gdVal('zkey'),
    remember_secret: !!((q('gdProfRemember') || {}).checked),
    customer_id: _gdVal('custid'),
    industry: (q('gdProfIndustry') || {}).value || sel.industry || '',
    baseline_packs: Array.from(document.querySelectorAll('.gd-prof-pack:checked')).map(x => x.value),
    scopes: typeof getSelectedScopes === 'function' ? getSelectedScopes() : [],
    frameworks: typeof getSelectedFrameworks === 'function' ? getSelectedFrameworks() : [],
    channels: typeof window.__dbChannelScope === 'function' ? window.__dbChannelScope() : {},
    notes: (q('gdProfNotes') || {}).value || '',
  };
}
async function _gdProfileSave(asNew) {
  const body = _gdProfileFormValues();
  if (asNew) { body.id = ''; body.name = prompt('Profile name (usually the customer name):', body.org_name || body.name || '') || ''; if (!body.name) return; }
  if (!(body.name || body.org_name || body.vanity_domain)) { alert('Give the profile a name, or fill in the organisation or vanity domain first.'); return; }
  GD.profileBusy = true; _gdProfilesRender();
  try {
    const r = await fetch('/api/tenant-profiles', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
    GD.profile = data.id; _gdSave();
    if (typeof setStatus === 'function') setStatus(`Profile "${data.name}" saved${data.has_secret ? ' with the secret remembered on this laptop' : ' (secret not stored)'}.`, 'success');
  } catch (e) { alert(`Could not save the profile: ${e.message}`); }
  GD.profileBusy = false;
  await _gdProfilesLoad(); _gdRender();
}
async function _gdProfileDelete() {
  const sel = _gdProfileSel(); if (!sel) return;
  if (!confirm(`Forget profile "${sel.name}" and its assessment history? The tenant itself is not touched.`)) return;
  await fetch(`/api/tenant-profiles/${encodeURIComponent(sel.id)}`, { method: 'DELETE' }).catch(() => null);
  GD.profile = ''; GD.profileHasSecret = false; _gdSave();
  await _gdProfilesLoad(); _gdRender();
}
function _gdHistoryHtml(p) {
  const hist = (p && p.history) || [];
  if (!hist.length) return `<div class="gd-need">No assessment recorded for this profile yet. Run the assessment with the profile selected and it will appear here.</div>`;
  const rows = hist.slice(-8).reverse().map(h => {
    const j = h.journey || {};
    const bl = (j.baselines || []).map(b => `${_gdE(b.name || b.id)}: stage ${b.stage || 0}${b.stage_name ? ` (${_gdE(b.stage_name)})` : ''}, ${b.score ?? 0}%`).join(' · ');
    return `<tr><td>${_gdE(new Date(h.at).toLocaleString())}</td><td>${h.score ?? '–'}%${h.maturity ? ` <span class="gd-dim">${_gdE(h.maturity)}</span>` : ''}</td><td>${j.stage != null ? `Stage ${j.stage} of 5 · ${j.score ?? 0}%` : '<span class="gd-dim">not measured</span>'}</td><td class="gd-dim">${bl || ''}</td></tr>`;
  }).join('');
  return `<table class="gd-hist"><thead><tr><th>When</th><th>Assessment</th><th>Journey</th><th>Per policy pack</th></tr></thead><tbody>${rows}</tbody></table>`;
}
function _gdProfilesRender() {
  const card = document.getElementById('configCard');
  if (!card) return;
  setTimeout(_gdScopeNote, 0);
  let bar = document.getElementById('gdProfiles');
  if (!bar) {
    bar = document.createElement('div'); bar.id = 'gdProfiles'; bar.className = 'gd-profiles';
    const h = card.querySelector(':scope > h2');
    (h || card).insertAdjacentElement(h ? 'afterend' : 'afterbegin', bar);
  }
  const sel = _gdProfileSel();
  const det = GD.profileDetail || sel || {};
  const last = det.last_assessed || (det.history || []).slice(-1)[0];
  const opts = ['<option value="">— no profile (type the details below) —</option>']
    .concat((GD.profiles || []).map(p => `<option value="${_gdE(p.id)}" ${p.id === GD.profile ? 'selected' : ''}>${_gdE(p.name)}${p.industry ? ` · ${_gdE(p.industry)}` : ''}${p.last_assessed ? ` · last ${_gdE(new Date(p.last_assessed.at).toLocaleDateString())}, ${p.last_assessed.score ?? '?'}%` : ''}</option>`)).join('');
  const packs = (GD.packs || []).map(p => `<label class="gd-prof-pack-l"><input type="checkbox" class="gd-prof-pack" value="${_gdE(p.id)}" ${(det.baseline_packs || []).includes(p.id) ? 'checked' : ''} onchange="_gdProfPacksChanged()"> ${_gdE(p.name || p.id)}</label>`).join('');
  bar.innerHTML = `
    <div class="gd-prof-top">
      <div class="gd-prof-title"><span class="gd-eyebrow">Tenant profiles</span>
        <div class="gd-need">Pick a saved customer and the form fills itself. Assessments run with a profile selected are recorded in its history, so the next visit shows movement on the journey.</div></div>
      <div class="gd-prof-controls">
        <select id="gdProfSelect" aria-label="Tenant profile" onchange="_gdProfileSelect(this.value)">${opts}</select>
        <button type="button" class="gd-btn quiet" onclick="_gdProfileSave(true)" ${GD.profileBusy ? 'disabled' : ''}>Save as new profile</button>
        ${sel ? `<button type="button" class="gd-btn primary" onclick="_gdProfileSave(false)" ${GD.profileBusy ? 'disabled' : ''}>Update "${_gdE(sel.name)}"</button><button type="button" class="gd-btn quiet" onclick="_gdProfileDelete()">Forget</button>` : ''}
      </div>
    </div>
    <div id="gdScopeNote" class="gd-need gd-scope" hidden></div>
    <details class="gd-prof-more" ${sel ? 'open' : ''}>
      <summary>${sel ? `Profile details${det.has_secret ? ' · secret remembered on this laptop' : ' · secret not stored (paste it below)'}` : 'Profile details (industry, applicable policy packs, notes, secret)'}</summary>
      <div class="gd-prof-grid">
        <label>Profile name<input id="gdProfName" value="${_gdE(det.name || '')}" placeholder="Acme Health"><span class="gd-need">Usually the customer name. Sample: <code>Acme Health</code></span></label>
        <label>Industry<select id="gdProfIndustry" onchange="_gdIndustryChanged(this.value)"><option value="">—</option>${GD_INDUSTRIES.map(i => `<option ${det.industry === i ? 'selected' : ''}>${i}</option>`).join('')}</select><span class="gd-need">Ticks the industry's policy packs below and pre-selects them in Deploy policy packs; add more packs as needed. It does not change any check.</span></label>
        <div class="gd-prof-packs"><span class="lbl">Policy packs that apply to this customer</span>${packs || '<span class="gd-need">No policy packs installed.</span>'}<span class="gd-need">The journey is measured only against the ticked policy packs. Leave all unticked to measure against every policy pack.</span></div>
        <label class="gd-prof-wide">Notes<textarea id="gdProfNotes" rows="2" placeholder="Kickoff 12 May; admin contact: Pat Lee; PHI pack agreed, enable SSL rule after change window.">${_gdE(det.notes || '')}</textarea></label>
        <label class="gd-prof-remember"><input type="checkbox" id="gdProfRemember" ${det.has_secret ? 'checked' : ''}> Remember the client secret on this laptop
          <span class="gd-need">Also the admin password and API key for the classic sign-in. Goes to this laptop's credential store when the optional <code>keyring</code> package is installed, otherwise into <code>tenant_profiles.json</code> next to the app (owner-only file); never sent back to the browser. Unticked, nothing secret is written and the form's values live only in this browser tab. Leave unticked on a shared machine.</span></label>
      </div>
      ${sel ? `<div class="gd-prof-hist"><span class="lbl">History${last ? ` · last assessed ${_gdE(new Date(last.at).toLocaleString())}, ${last.score ?? '?'}%${last.journey ? `, journey stage ${last.journey.stage || 0} of 5` : ''}` : ''}</span>${_gdHistoryHtml(det)}</div>` : ''}
    </details>`;
}

// ── Boot ───────────────────────────────────────────────────────────
(function () {
  const anchor = document.getElementById('stepBar');
  if (!anchor) return;
  _gdLoad();
  fetch('/api/health', { cache: 'no-store' }).then(r => r.json()).then(d => { GD.about = d; _gdRender(); }).catch(() => {});
  const panel = document.createElement('section');
  panel.id = 'gdPanel'; panel.className = 'gd-panel'; panel.setAttribute('aria-label', 'Start here');
  anchor.insertAdjacentElement('afterend', panel);
  _gdApplyMode();
  _gdRender();
  _gdProfilesLoad().then(() => { const p = GD.profileDetail; if (p && !_gdVal('vd')) _gdProfileFill(p); _gdRender(); });
  // Keep the step chips honest as the operator types, runs, and deploys.
  ['vd', 'cid', 'csec', 'cloud'].forEach(id => { const el = document.getElementById(id); if (el) el.addEventListener('input', _gdRender); });
  GD.timer = setInterval(_gdRender, 2500);
  const fab = document.createElement('button');
  fab.type = 'button'; fab.id = 'gdHelpFab'; fab.className = 'gd-btn primary'; fab.textContent = '? Help';
  fab.setAttribute('aria-label', 'Open help and glossary'); fab.onclick = () => _gdHelp(true);
  document.body.appendChild(fab);
})();

// The report tabs share the saved theme; when it is switched there, follow here.
window.addEventListener('storage', e => {
  if (e.key !== 'zassess_theme' || typeof _applyTheme !== 'function') return;
  _applyTheme(e.newValue === 'light' ? 'light' : 'dark');
});
