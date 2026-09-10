// ── Guide: Start-here panel, Guided mode, Test connection, Help drawer ──
// Injected by the server after index.html's inline script. Everything here
// is additive: it reads the page's existing controls (tenant fields, the
// Run Assessment button, the results card, Deploy Studio) and explains
// them in plain language so a first-time operator can follow the four
// steps without knowing ZIA DLP internals.

const GD = { conn: null, testing: false, mode: 'guided', helpOpen: false, timer: null,
             profile: '', profileHasSecret: false, profiles: [], profileDetail: null, profileBusy: false, packs: [] };
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
  const creds = !!(_gdVal('vd') && _gdVal('cid') && (_gdVal('csec') || (GD.profile && GD.profileHasSecret)));
  const sameTenant = GD.conn && GD.conn.vd === _gdVal('vd');
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
      what: 'Enter the customer\'s cloud, vanity domain, API client ID and client secret in Tenant Configuration and click Authenticate. Nothing is changed in the tenant; the tool only reads.',
      need: 'A OneAPI API client from ZIdentity (Integration > API Clients) with a ZIA role that can read DLP dictionaries, engines and rules. Ask the customer\'s Zscaler admin for these four values.',
      status: sameTenant && GD.conn.ok
        ? `Connected to ${_gdE(GD.conn.label)}: ${GD.conn.dictionaries} dictionaries, ${GD.conn.engines} engines, ${GD.conn.web_rules} web DLP rules.`
        : (creds ? 'Details entered. Click Authenticate before going further.' : 'Fill in the four tenant fields, then click Authenticate.'),
      actions: [
        { label: 'Go to tenant details', fn: '_gdGoConfig()', kind: creds ? 'quiet' : 'primary' },
        { label: GD.testing ? 'Authenticating…' : 'Authenticate', fn: '_gdTest()', kind: creds ? 'primary' : 'quiet', disabled: !creds || GD.testing },
      ],
    },
    {
      n: 2, title: 'Assess the tenant',
      state: assessed ? 'done' : (connected ? 'ready' : 'todo'),
      what: 'Runs 300+ automated checks against the tenant and produces a maturity score with a list of findings. Takes about 90 seconds. Read-only.',
      need: 'A successful Authenticate in step 1, your organisation and assessor names, and a scope. For a DLP engagement keep the default scopes ticked.',
      status: running ? 'Running… the progress card below shows each check as it completes.' : (assessed ? 'Assessment complete. Results are below.' : (connected ? 'Choose a scope in Tenant Configuration, then click Run assessment here.' : 'Authenticate in step 1 first.')),
      actions: [{ label: running ? 'Running…' : 'Run assessment', fn: '_gdRun()', kind: 'primary', disabled: !connected || running }],
    },
    {
      n: 3, title: 'Read the results',
      state: assessed ? 'ready' : 'todo',
      what: 'The Summary card gives the score and maturity level. Detailed Findings lists every failed or warned check with what it means and how to fix it. Regulatory Alignment maps findings to frameworks the customer cares about.',
      need: 'Nothing. Walk the customer through Critical findings first; they are the ones that expose data today.',
      status: assessed ? 'Scroll down to Summary, Scores by Section and Detailed Findings.' : 'Available after the assessment runs.',
      actions: [{ label: 'Jump to results', fn: '_gdGoResults()', kind: 'quiet', disabled: !assessed }],
    },
    {
      n: 4, title: 'Pick a baseline and run the preflight',
      state: deployed ? 'done' : (assessed || (sameTenant && GD.conn && GD.conn.ok) ? 'ready' : 'todo'),
      what: 'A baseline is a complete, layered policy design for one situation: Healthcare PHI, CUI markings, Zscaler\'s enterprise best practice, Endpoint DLP, and so on. Each card says who it is for and when to use it. Preflight reads the tenant and shows exactly what would be created, what already exists and is kept, and what the impact is. Nothing is written.',
      need: 'A connected tenant. Preflight works in read-only mode; it is the plan you show the customer.',
      status: deployed ? `Last deployment ${_gdE(deployed.status)} on ${_gdE(deployed.at)}: ${deployed.created || 0} created.` : 'Open Deploy Policy Packs, tick a baseline, click Run preflight, then read the Impact cards and the plan.',
      actions: [{ label: 'Open Deploy Policy Packs', fn: 'openDlpPacksModal()', kind: 'primary' }],
    },
    {
      n: 5, title: 'Close the gap: deploy from here, or hand off as Terraform',
      state: deployed ? 'done' : (assessed || (sameTenant && GD.conn && GD.conn.ok) ? 'ready' : 'todo'),
      what: 'Two ways to create the missing objects. <strong>Deploy from here</strong>: enable write mode in Deploy Policy Packs, review, tick the consent box, deploy; every rule arrives disabled and nothing the customer already has is overwritten. <strong>Hand off as Terraform</strong>: for customers whose platform team manages Zscaler as code, download the same baseline as a Terraform workspace; in gap mode it imports what exists so their first plan is exactly the gap.',
      need: 'Deploying from here needs write mode (a confirmation phrase, until the server restarts). The Terraform route needs nothing from this tool after the download; the platform team needs an API client with write access.',
      status: deployed ? 'Deployed. Activate in the ZIA portal, then enable rules one by one.' : 'Choose the route the customer prefers. Both start from the same preflight.',
      actions: [{ label: 'Deploy Policy Packs', fn: 'openDlpPacksModal()', kind: 'primary' }, { label: 'Terraform hand-off', fn: "openToolTab('terraform')", kind: 'quiet' }],
    },
    {
      n: 6, title: 'Move the tenant to Evaluate All Rules',
      state: assessed || (sameTenant && GD.conn && GD.conn.ok) ? 'ready' : 'todo',
      what: 'By default ZIA stops at the first matching DLP rule, so a broad monitor rule near the top silently shadows every block rule below it. Evaluate All Rules lets every matching rule fire and log its own incident, which is what a layered policy (monitor + block + caution) needs. The Inline DLP Rule Migration wizard reads the current mode, reorders the rules so the switch is safe, and shows you the plan before anything changes.',
      need: 'Check 5.20 in the assessment says whether the tenant is already in Evaluate All Rules mode and whether the current order is safe to switch. The switch itself is made in the ZIA Admin Portal under Policy > Data Loss Prevention > Advanced Settings.',
      status: 'Open the Inline DLP Rule Migration card below the results and follow its five steps.',
      actions: [{ label: 'Open Rule Migration', fn: '_gdGoMigration()', kind: 'primary' }],
    },
    {
      n: 7, title: 'Come back and measure the journey',
      state: deployed ? 'ready' : 'todo',
      what: 'On the next visit, run the assessment again with the same tenant profile. The Data governance journey card places the tenant on the five-stage ladder (Foundation, Policies deployed, Visibility, Containment, Enforcement), names the exact rules to enable or harden next, and compares with the previous visit. Nothing the customer changed is reverted; an enabled rule or a hardened action is progress.',
      need: 'The tenant profile you saved in step 1, so the history lines up.',
      status: GD.profile ? 'Profile selected: the next assessment is recorded against it.' : 'Save a tenant profile in Tenant Configuration so history is kept.',
      actions: [{ label: 'Run assessment', fn: '_gdRun()', kind: 'primary', disabled: !creds }, { label: 'Where is this tenant?', fn: 'openDlpPacksModal()', kind: 'quiet' }],
    },
  ];
}
function _gdGoMigration() {
  const card = [...document.querySelectorAll('div.card')].find(c => ((c.querySelector(':scope > h2, :scope > div h2') || {}).textContent || '').includes('Inline DLP Rule Migration'));
  if (!card) { alert('The Inline DLP Rule Migration card is not on this page.'); return; }
  const h = card.querySelector('h2.collapsible');
  if (h && card.classList.contains('collapsed')) h.click();
  card.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

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
  if (a.is_git_checkout === false) {
    s += ' · <strong>not a git checkout</strong>: it cannot be updated in place.' + btn('How to update', true);
  } else if (a.latest_commit && a.git_commit && a.git_commit !== 'unknown' && a.latest_commit !== a.git_commit) {
    s += ` · <strong>update available</strong> (GitHub is on ${_gdE(a.latest_commit)})` + btn('Update app now', true);
  } else if (a.latest_commit) {
    s += ' · up to date' + btn('Update app', false) + ' <button type="button" class="gd-link" onclick="_gdUpdateCheck()">Check again</button>';
  } else {
    s += ` · <strong>could not check GitHub</strong>${a.latest_commit_error ? ` (${_gdE(a.latest_commit_error)})` : ''}` + btn('Update app', true) + ' <button type="button" class="gd-link" onclick="_gdUpdateCheck()">Check again</button>';
  }
  return s + _gdTlsNote(a.tls);
}
function _gdUpdateBox(html, show = true) {
  const box = document.getElementById('gdUpdate');
  if (!box) return;
  box.hidden = !show; box.innerHTML = html;
}
async function _gdUpdateCheck() {
  _gdUpdateBox('<span class="gd-upd-line">Checking GitHub…</span>');
  try {
    const st = await (await fetch('/api/app/update/status?refresh=1', { cache: 'no-store' })).json();
    GD.about = Object.assign({}, GD.about, { git_commit: st.local_commit || GD.about.git_commit, latest_commit: st.remote_commit, latest_commit_error: st.remote_error || null, is_git_checkout: st.is_git_checkout });
    _gdRender();
    const note = st.reason && st.can_update ? `<div class="gd-upd-line soft">${_gdE(st.reason)}</div>` : '';
    if (st.reason && !st.can_update) _gdUpdateBox(`<span class="gd-upd-line warn">${_gdE(st.reason)}</span>`);
    else if (st.update_available) _gdUpdateBox(`<span class="gd-upd-line">GitHub is on build ${_gdE(st.remote_commit)}; this install is on ${_gdE(st.local_commit)}.</span>${note}`);
    else _gdUpdateBox(`<span class="gd-upd-line ok">Up to date (build ${_gdE(st.local_commit || '?')}).</span>`);
  } catch (e) { _gdUpdateBox(`<span class="gd-upd-line warn">Could not check: ${_gdE(e.message)}</span>`); }
}
function _gdUpdateHelp() {
  const cmd = 'cd /d "%USERPROFILE%" && (if exist "DLP-Check\\\\.git" (cd /d "%USERPROFILE%\\\\DLP-Check" && git fetch origin && git checkout main && git pull --ff-only origin main) else (git clone https://github.com/berserkerjay/DLP-Check.git && cd /d "%USERPROFILE%\\\\DLP-Check")) && call INSTALL_Zscaler_Assessment.bat && call UPDATE_Zscaler_Assessment.bat';
  _gdUpdateBox(`<div class="gd-upd-line">This copy was not installed with git, so it cannot pull updates. Run this once in a Command Prompt; it clones the repository under your user folder, installs it and repoints the shortcuts. Copy <code>local_settings.bat</code> from the old folder afterwards.</div>
    <pre class="gd-upd-cmd" id="gdUpdCmd">${_gdE(cmd)}</pre>
    <button type="button" class="gd-btn quiet gd-btn-sm" onclick="navigator.clipboard && navigator.clipboard.writeText(document.getElementById('gdUpdCmd').textContent).then(() => announce('Command copied'))">Copy command</button>`);
}
async function _gdUpdateApp() {
  if (GD.about && GD.about.is_git_checkout === false) { _gdUpdateHelp(); return; }
  const btn = document.getElementById('gdUpdateBtn'); if (btn) { btn.disabled = true; btn.textContent = 'Updating…'; }
  const lines = [];
  const show = (extra = '') => _gdUpdateBox(`<div class="gd-upd-steps">${lines.map(l => `<div class="gd-upd-line ${l.ok === false ? (l.soft ? 'soft' : 'warn') : l.ok ? 'ok' : ''}">${l.ok === false ? (l.soft ? '⚠' : '✗') : l.ok ? '✓' : '…'} ${_gdE(l.name)}${l.detail ? ` <span class="dim">— ${_gdE(l.detail)}</span>` : ''}</div>`).join('')}${extra}</div>`);
  lines.push({ name: 'Pulling the latest code from GitHub', ok: null }); show();
  let res;
  try {
    const r = await fetch('/api/app/update', { method: 'POST' });
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
  try {
    const r = await fetch('/api/app/restart', { method: 'POST' });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  } catch (e) {
    lines[lines.length - 1] = { name: 'Restart could not be scheduled', ok: false, detail: e.message + '. Close the app with STOP_Zscaler_Assessment.bat and open it again from the shortcut.' }; show(); return;
  }
  // Wait for the new process: health answers with the new build.
  const started = Date.now();
  const poll = async () => {
    try {
      const h = await (await fetch('/api/health', { cache: 'no-store' })).json();
      if (h.git_commit && h.git_commit === res.after) { lines[lines.length - 1] = { name: `Restarted on build ${h.git_commit}. Reloading…`, ok: true }; show(); setTimeout(() => location.reload(), 600); return; }
    } catch (_) { /* server is down while it restarts */ }
    if (Date.now() - started > 90000) { lines[lines.length - 1] = { name: 'The app did not come back within 90 seconds', ok: false, detail: 'Open it again from the desktop shortcut; the update itself succeeded.' }; show(); return; }
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
  host.innerHTML = `
    <div class="gd-head">
      <div>
        <div class="gd-eyebrow">Start here</div>
        <h2 class="gd-title">Seven steps from "unknown tenant" to "governed data"</h2>
        <p class="gd-sub">Follow the steps in order. Each one explains what it does, what you need, and what to click. Nothing is written to the customer's tenant until step 5, and only after you approve a plan or hand it off as Terraform.</p>
        <p class="gd-sub gd-where" id="gdWhere">${_gdWhereHtml()}</p>
        <div id="gdUpdate" class="gd-update" hidden></div>
      </div>
      <div class="gd-controls">
        <label class="gd-switch" title="Guided mode hides the Compliance Coverage card so the seven steps stay in focus. Every tool stays available in the toolbar above.">
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
        <div class="gd-step-n"><span>${s.state === 'done' ? '✓' : s.n}</span></div>
        <div class="gd-step-body">
          <div class="gd-step-top"><h3>${_gdE(s.title)}</h3><span class="gd-chip ${s.state}">${{ done: 'Done', ready: 'Ready', todo: 'Not yet' }[s.state]}</span></div>
          <p class="gd-what">${s.what}</p>
          <p class="gd-need"><strong>You need:</strong> ${s.need}</p>
          <div class="gd-status">${s.status}</div>
          ${s.n === 1 ? _gdConnHtml() : ''}
          <div class="gd-actions">${s.actions.map(a => `<button type="button" class="gd-btn ${a.kind}" ${a.disabled ? 'disabled' : ''} onclick="${a.fn}">${_gdE(a.label)}</button>`).join('')}</div>
        </div>
      </li>`).join('')}
    </ol>`;
}

function _gdAuthStatus() {
  const st = document.getElementById('authStatus');
  if (!st) return;
  const c = GD.conn;
  if (GD.testing) { st.textContent = 'Authenticating…'; st.className = 'auth-status'; return; }
  if (!c || c.vd !== _gdVal('vd')) { st.textContent = ''; st.className = 'auth-status'; return; }
  st.className = 'auth-status ' + (c.ok ? 'ok' : 'bad');
  st.textContent = c.ok ? `Connected to ${c.label}. Now run the assessment from Start here, step 2.` : `Could not connect: ${c.cause || 'see Start here, step 1'}`;
}
function _gdConnHtml() {
  const c = GD.conn;
  if (!c || c.vd !== _gdVal('vd')) return '';
  if (c.ok) {
    return `<div class="gd-conn ok"><strong>Connected.</strong> ${_gdE(c.label)} · ${c.dictionaries} dictionaries (${c.custom_dictionaries} custom) · ${c.engines} engines · ${c.web_rules} web DLP rules${(c.problems || []).length ? `<div class="gd-warn">${c.problems.map(p => _gdE(p)).join('<br>')}</div>` : ''}</div>`;
  }
  return `<div class="gd-conn bad"><strong>Could not connect.</strong> ${_gdE(c.cause || '')}<div class="gd-fix"><strong>What to do:</strong> ${_gdE(c.fix || '')}</div>${c.raw ? `<details><summary>Technical detail</summary><code>${_gdE(c.raw)}</code></details>` : ''}</div>`;
}

// ── Actions ────────────────────────────────────────────────────────
function _gdGoConfig() {
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
  if (btn && btn.disabled) { alert('An assessment is already running.'); return; }
  // The results open in their own tab (progress first, then the report),
  // with a link back here; they stay on this page as well.
  if (typeof openToolTab === 'function') openToolTab('results', 'run');
  else if (typeof runAssessment === 'function') runAssessment(); else if (btn) btn.click();
  _gdRender();
}
async function _gdTest() {
  if (typeof migrateCredBody !== 'function') return;
  const body = migrateCredBody(); delete body.customer_id;
  GD.testing = true; _gdRender();
  try {
    const r = await fetch('/api/tenant/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      const d = (data && typeof data.detail === 'object') ? data.detail : { cause: 'The connection failed.', fix: 'Re-check the tenant details and try again.', raw: String(data.detail || `HTTP ${r.status}`) };
      GD.conn = { ok: false, vd: body.vanity_domain, label: d.tenant_label, cause: d.cause, fix: d.fix, raw: d.raw };
    } else {
      GD.conn = { ok: true, vd: body.vanity_domain, label: data.tenant_label, dictionaries: data.dictionaries, custom_dictionaries: data.custom_dictionaries,
                  engines: data.engines, web_rules: data.web_rules, problems: data.problems || [], at: new Date().toISOString() };
      if (typeof announce === 'function') announce(`Connected to ${data.tenant_label}.`);
    }
  } catch (e) {
    GD.conn = { ok: false, vd: body.vanity_domain, cause: 'The tool\'s own server did not answer.', fix: 'Make sure the server window is still open, then try again.', raw: e.message };
  } finally {
    GD.testing = false; _gdSave(); _gdRender();
  }
}
function _gdSetMode(mode) {
  GD.mode = mode; _gdSave(); _gdApplyMode(); _gdRender();
}

// Guided mode hides the advanced tools. Cards are found by their heading
// text so index.html needs no markup changes.
const GD_ADVANCED_HEADINGS = ['Compliance Coverage'];
// The toolbar is grouped (Find the gaps / Close the gaps / Reference) with a
// tooltip per tool, so guided mode leaves it intact and only hides the
// Compliance Coverage card.
const GD_ADVANCED_BUTTONS = [];
function _gdApplyMode() {
  document.body.classList.toggle('gd-guided', GD.mode === 'guided');
  document.querySelectorAll('div.card').forEach(card => {
    const h = card.querySelector(':scope > h2, :scope > h3, :scope > div h2');
    const t = (h ? h.textContent : '').trim();
    if (GD_ADVANCED_HEADINGS.some(x => t.startsWith(x))) card.classList.add('gd-advanced');
  });
  GD_ADVANCED_BUTTONS.forEach(fn => {
    document.querySelectorAll(`button[onclick="${fn}"]`).forEach(b => b.classList.add('gd-advanced'));
  });
}

// ── Help drawer ────────────────────────────────────────────────────
const GD_GLOSSARY = [
  ['Dictionary', 'The thing to look for: a list of phrases and/or regular-expression patterns (for example, "MRN" next to a 7-digit number). Zscaler ships predefined ones (SSN, credit cards, medical terms); packs add custom ones.'],
  ['Engine', 'How dictionaries combine into a decision, using AND / OR and match counts, for example "(SSN more than 4 times) OR (passport number at least once)". Rules point at engines, never directly at dictionaries.'],
  ['Rule (policy)', 'Where and how an engine is enforced: which traffic (web uploads, email, SaaS apps, endpoints), which users, and the action. Rules run in order from the top; the first match wins unless the tenant is set to evaluate all rules.'],
  ['Action: ALLOW vs BLOCK', 'ALLOW means monitor: the transaction goes through and an incident is logged. BLOCK stops it. CONFIRM asks the user first. Every pack ships its rules in ALLOW or BLOCK as designed, but DISABLED, so nothing happens until you enable a rule.'],
  ['Severity', 'The label an incident gets in reports (INFO, LOW, MEDIUM, HIGH). It does not change what the rule does. Packs ship at INFO; raise it once a rule is tuned.'],
  ['Policy pack', 'A folder of dictionaries, engines and rules for one purpose: CJIS, the Fed pack, Zscaler\'s enterprise best practice, healthcare PHI. Deploying a pack creates those objects in the tenant.'],
  ['Baseline', 'A pack that is the reference a tenant is measured against. Deploy it greenfield (empty tenant: everything is created) or brownfield (existing tenant: what exists is kept exactly as the customer has it, the rest is created). Nothing is ever overwritten. Objects the baseline does not define are never touched.'],
  ['Greenfield / brownfield', 'Greenfield: none of the pack\'s objects exist yet, so the whole pack is created from scratch. Brownfield: some already exist (perhaps from an earlier deploy, perhaps built by hand); they are kept, only the missing ones are created.'],
  ['Preflight', 'The read-only check Deploy Studio runs before anything is written: it reads the tenant, works out what is missing, what already exists, what conflicts, and what the impact would be. You approve that exact plan.'],
  ['Plan hash', 'A fingerprint of the plan you approved. If the tenant changes between approval and deploy, the fingerprint no longer matches and nothing is written until you review again.'],
  ['Journey (where is this tenant?)', 'The data-governance journey has five stages: Foundation (dictionaries and engines exist), Policies deployed (every rule exists), Visibility (SSL decrypts the risky app classes and DLP rules are enabled), Containment (Cloud App Control, File Type and URL rules are enabled), Enforcement (DLP rules block). The assessment and the pack card place the tenant on that ladder and list the exact rules to enable or harden next.'],
  ['Customized', 'A baseline object the customer changed: a rule they enabled, an action they hardened from ALLOW to BLOCK, a dictionary they tuned. That is progress, not drift. It is kept as-is and shown as customized; converge mode (an explicit API option) is the only thing that overwrites it.'],
  ['Activation', 'ZIA saves changes as pending. After a deploy, an admin must click Activate in the ZIA Admin Portal for the new rules to take effect for users.'],
  ['Read-only vs write mode', 'The server starts read-only: assessment, preflight and journey checks all work, deploying is refused. Deploy Policy Packs shows the current mode and an Enable write mode button (type the confirmation phrase; it lasts until the server restarts). START_Zscaler_Assessment_WRITES_ENABLED.bat starts in write mode from the outset. Stay read-only when you only want to show the customer the plan.'],
  ['OneAPI credentials', 'The client ID and secret of an API client created in ZIdentity, plus the vanity domain (the short name in the login URL, acme for acme.zslogin.net) and the cloud (Production for almost everyone).'],
  ['Terraform hand-off', 'The same pack as a Terraform workspace for the official zscaler/zia provider, for customers whose platform team manages Zscaler as code. Gap mode reads the tenant and imports existing objects so the first plan shows exactly the gap; static mode needs no credentials. Terraform then owns the objects: a later plan shows how the tenant moved, and apply would converge it, so use plan to assess and apply deliberately.'],
  ['Outbound Email DLP', 'Rules that inspect mail leaving onboarded Microsoft 365 / Gmail tenants (Administration > SaaS Application Tenants). The baselines ship a monitor-only email rule; preflight skips it, with the reason, when no email tenant is onboarded.'],
];
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
      <p>DLP-Check does two things. First it <strong>assesses</strong> a Zscaler tenant against a checklist of best practices and gives it a score. Then it <strong>closes the gaps</strong> by deploying policy packs: ready-made DLP and containment configuration that is checked against the tenant and approved by you before anything is written, into an empty tenant or on top of what is already there. Afterwards it <strong>measures the journey</strong>: how far the tenant has taken that baseline, from deployed to monitoring to enforcing, and what to enable next.</p>
      <p>A good first engagement: connect, run the assessment, walk the customer through the critical findings, then run a preflight for the pack that matches their regulation and show them the plan. Deploy only when the customer has agreed and the server is running with writes enabled.</p>
      <h3>Tools at a glance</h3>
      <dl>
        <dt>Assessment (Run Assessment)</dt><dd>300+ read-only checks against the tenant, a score, findings with fixes, and the Data governance journey card for every baseline pack.</dd>
        <dt>Tenant profiles</dt><dd>One saved record per customer (details, scopes, applicable baselines, optional remembered secret) with the history of every assessment.</dd>
        <dt>Deploy Policy Packs</dt><dd>Pick a baseline, choose which DLP channels its engines go into (Inline Web, Endpoint DLP, SaaS Security, Outbound Email: a ticked channel the pack has no rule for gets a monitor-only rule with the pack's engines, an unticked one is skipped), preflight against the tenant, review the exact plan, enable write mode, approve, deploy. Every rule arrives disabled; existing objects are kept. <em>Where is this tenant?</em> on a baseline card measures the journey. Every deployment is recorded under <em>Previous deployments</em>, where <em>Undo</em> deletes exactly what it created.</dd>
        <dt>Terraform hand-off</dt><dd>The same baseline as a Terraform workspace for the official zscaler/zia provider, for platform teams that manage Zscaler as code. Gap mode imports what already exists so the first plan is exactly the gap. The repository also carries a validated workspace per pack under terraform/.</dd>
        <dt>Evaluate All Rules (Inline DLP Rule Migration)</dt><dd>Reorders web DLP rules so the tenant can switch from first-match-wins to Evaluate All Rules safely; check 5.20 in the assessment says whether it is needed.</dd>
        <dt>Bypass / Non-Inspected</dt><dd>Every SSL bypass, allow rule and Client Connector exemption that lets traffic skip inspection, with exports. Opens in its own tab.</dd>
        <dt>SSL Inspection Flow</dt><dd>Live flow diagram: for each DLP-relevant traffic class (file sharing, webmail, AI, social, uncategorised sites…) which SSL rule decides, whether it is decrypted, and whether inline Web DLP can see it. Gaps are highlighted with the fix. Refresh or auto-refresh from the tab.</dd>
        <dt>DLP Efficacy</dt><dd>Scores every custom dictionary and engine for false-positive risk and lets you test sample text against them.</dd>
        <dt>Best Practices</dt><dd>Curated Zscaler best-practice articles rated by source credibility. <em>Update library now</em> reads the sitemaps of help.zscaler.com, the Zscaler blog and the developer portal (and walks the partner sites), adds every new best-practice or leading-practice article, and shows per source whether it answered and why not. New finds are kept across restarts; a background refresh runs every 6 hours.</dd>
        <dt>Zscaler Updates</dt><dd>A check of PyPI and help.zscaler.com for SDK and documentation changes since last time.</dd>
        <dt>Packs from a design file (command line)</dt><dd><code>python tools/pack_from_design.py &lt;pack&gt;</code> turns a DLP engineer's dictionary/engine design into a pack, enforcing ZIA's documented limits.</dd>
      </dl>
      <h3>Glossary</h3>
      <dl>${GD_GLOSSARY.map(([t, d2]) => `<dt>${_gdE(t)}</dt><dd>${_gdE(d2)}</dd>`).join('')}</dl>
      <h3>If something goes wrong</h3>
      <ul>
        <li><strong>"Could not connect"</strong> under step 1 tells you the cause and the fix. Nine times out of ten it is a pasted secret that was not the real secret, or a machine behind TLS inspection.</li>
        <li><strong>"0 endpoints probed" or empty results</strong>: the credentials were rejected; test the connection.</li>
        <li><strong>Preflight says blocked</strong>: read the red card. It names the object and the missing prerequisite (a predefined dictionary, an onboarded SaaS tenant, a licensed feature).</li>
        <li><strong>"Write actions require ENABLE_WRITE_ACTIONS"</strong> or a read-only banner in Deploy Policy Packs: click <em>Enable write mode</em> there and type the phrase, or start the server with START_Zscaler_Assessment_WRITES_ENABLED.bat.</li>
      </ul>
      <p class="gd-dim">Full walkthrough: GETTING_STARTED.md in the project folder.</p>
    </div>`;
  d.querySelector('.gd-help-sheet').focus?.();
}

// ── Journey card on the assessment results ─────────────────────────
// The assessment measures the tenant against every baseline pack; this
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
    card.innerHTML = `<h2>Data governance journey</h2><p class="gd-sub">Could not measure the tenant against the baselines: ${E(j.error || 'unknown error')}. The assessment itself is complete.</p>`;
    return;
  }
  if (j.status === 'pending') {
    card.innerHTML = `<h2>Data governance journey</h2><p class="gd-sub"><span class="gd-spin" aria-hidden="true"></span> Measuring the tenant against each baseline pack${j.current ? ` — ${E(j.current.replace(/^Data governance journey: /, ''))}` : ''}. The results above are final; this card fills in when the measurement finishes.</p>`;
    return;
  }
  const stages = (j.stages || []).map(s => `<li><b>${E(s.name)}</b> — ${E(s.what)}</li>`).join('');
  const rows = (j.baselines || []).map(b => `<div class="dz-journey ${b.state === 'governed' ? 'ok' : (b.state === 'blocked' ? 'fail' : (b.state === 'not_started' ? 'info' : 'warn'))}"><h3>${E(b.name)}${b.version ? ` <span class="gd-dim">v${E(b.version)}</span>` : ''}</h3>${typeof _dzJourneyRowHtml === 'function' ? _dzJourneyRowHtml(b, { max: 6 }) : `Stage ${b.stage} of 5 (${E(b.stage_name)})`}</div>`).join('');
  const overall = { not_started: 'Not started: none of the baselines has been deployed yet.', in_progress: 'In progress: baselines are deployed but not yet fully enabled and enforcing.', governed: 'Governed: every baseline is deployed, enabled and enforcing.', blocked: 'Blocked: something a baseline needs is missing from the tenant.' }[j.status] || j.status;
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
    <p class="gd-sub">Where this tenant stands against each baseline pack, measured read-only during the assessment. <strong>${E(overall)}</strong> Overall stage ${j.stage || 0} of 5, ${j.score || 0}% of the way. Deploying a baseline (Deploy Studio) creates what is missing and keeps everything the customer already has; enabling and hardening rules in the ZIA portal moves the tenant up the ladder.</p>
    ${trend}
    <details class="dz-fold"><summary>The five stages</summary><ol class="dz-next">${stages}</ol></details>
    ${rows || '<p class="gd-sub">No baseline packs are installed.</p>'}`;
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
// details, scopes, applicable baselines, optional remembered secret, and
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
      GD.packs = (pr.packs || []).filter(p => p.baseline);
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
function _gdProfileFill(p) {
  const set = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.value = v; };
  set('org', p.org_name || ''); set('assessor', p.assessor || ''); set('cloud', p.cloud || 'production');
  set('vd', p.vanity_domain || ''); set('cid', p.client_id || ''); set('custid', p.customer_id || '');
  set('csec', '');
  if (Array.isArray(p.scopes) && p.scopes.length && typeof setSelectedScopes === 'function') setSelectedScopes(p.scopes);
  if (Array.isArray(p.frameworks) && p.frameworks.length) document.querySelectorAll('.fw-cb').forEach(cb => { cb.checked = p.frameworks.includes(cb.value); });
}
async function _gdProfileSelect(id) {
  GD.profile = id || ''; _gdSave();
  await _gdProfilesLoad();
  const p = GD.profileDetail;
  if (p) { _gdProfileFill(p); if (typeof setStatus === 'function') setStatus(`Profile "${p.name}" loaded${p.has_secret ? ' (secret remembered on this laptop)' : ' — paste the client secret'}.`, 'success'); }
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
    remember_secret: !!((q('gdProfRemember') || {}).checked),
    customer_id: _gdVal('custid'),
    industry: (q('gdProfIndustry') || {}).value || sel.industry || '',
    baseline_packs: Array.from(document.querySelectorAll('.gd-prof-pack:checked')).map(x => x.value),
    scopes: typeof getSelectedScopes === 'function' ? getSelectedScopes() : [],
    frameworks: typeof getSelectedFrameworks === 'function' ? getSelectedFrameworks() : [],
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
  return `<table class="gd-hist"><thead><tr><th>When</th><th>Assessment</th><th>Journey</th><th>Per baseline</th></tr></thead><tbody>${rows}</tbody></table>`;
}
function _gdProfilesRender() {
  const card = document.getElementById('configCard');
  if (!card) return;
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
  const packs = (GD.packs || []).map(p => `<label class="gd-prof-pack-l"><input type="checkbox" class="gd-prof-pack" value="${_gdE(p.id)}" ${(det.baseline_packs || []).includes(p.id) ? 'checked' : ''}> ${_gdE(p.name || p.id)}</label>`).join('');
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
    <details class="gd-prof-more" ${sel ? 'open' : ''}>
      <summary>${sel ? `Profile details${det.has_secret ? ' · secret remembered on this laptop' : ' · secret not stored (paste it below)'}` : 'Profile details (industry, applicable baselines, notes, secret)'}</summary>
      <div class="gd-prof-grid">
        <label>Profile name<input id="gdProfName" value="${_gdE(det.name || '')}" placeholder="Acme Health"><span class="gd-need">Usually the customer name. Sample: <code>Acme Health</code></span></label>
        <label>Industry<select id="gdProfIndustry"><option value="">—</option>${GD_INDUSTRIES.map(i => `<option ${det.industry === i ? 'selected' : ''}>${i}</option>`).join('')}</select><span class="gd-need">Helps you pick the right baseline; it does not change any check.</span></label>
        <div class="gd-prof-packs"><span class="lbl">Baselines that apply to this customer</span>${packs || '<span class="gd-need">No baseline packs installed.</span>'}<span class="gd-need">The journey is measured only against the ticked baselines. Leave all unticked to measure against every baseline.</span></div>
        <label class="gd-prof-wide">Notes<textarea id="gdProfNotes" rows="2" placeholder="Kickoff 12 May; admin contact: Pat Lee; PHI pack agreed, enable SSL rule after change window.">${_gdE(det.notes || '')}</textarea></label>
        <label class="gd-prof-remember"><input type="checkbox" id="gdProfRemember" ${det.has_secret ? 'checked' : ''}> Remember the client secret on this laptop
          <span class="gd-need">Stored in <code>tenant_profiles.json</code> next to the app (owner-only file, never sent back to the browser). Leave unticked on a shared machine.</span></label>
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
