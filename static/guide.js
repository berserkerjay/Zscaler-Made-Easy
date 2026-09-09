// ── Guide: Start-here panel, Guided mode, Test connection, Help drawer ──
// Injected by the server after index.html's inline script. Everything here
// is additive: it reads the page's existing controls (tenant fields, the
// Run Assessment button, the results card, Deploy Studio) and explains
// them in plain language so a first-time operator can follow the four
// steps without knowing ZIA DLP internals.

const GD = { conn: null, testing: false, mode: 'guided', helpOpen: false, timer: null };
const GD_LS_MODE = 'zassess_guide_mode';
const GD_LS_CONN = 'zassess_guide_conn';
const GD_LS_DEPLOY = 'zassess_last_deploy';

const _gdE = s => (typeof escapeHtml === 'function' ? escapeHtml(String(s == null ? '' : s)) : String(s == null ? '' : s));
const _gdVal = id => ((document.getElementById(id) || {}).value || '').trim();

function _gdLoad() {
  try {
    GD.mode = localStorage.getItem(GD_LS_MODE) || 'guided';
    const c = localStorage.getItem(GD_LS_CONN); if (c) GD.conn = JSON.parse(c);
  } catch (e) { /* storage may be unavailable */ }
}
function _gdSave() {
  try {
    localStorage.setItem(GD_LS_MODE, GD.mode);
    if (GD.conn) localStorage.setItem(GD_LS_CONN, JSON.stringify(GD.conn));
  } catch (e) { /* ignore */ }
}

// ── Step state ────────────────────────────────────────────────────
function _gdSteps() {
  const creds = !!(_gdVal('vd') && _gdVal('cid') && _gdVal('csec'));
  const sameTenant = GD.conn && GD.conn.vd === _gdVal('vd');
  const results = document.getElementById('results');
  const assessed = !!(results && results.offsetParent !== null && results.textContent.trim().length > 50);
  let deployed = null;
  try { deployed = JSON.parse(localStorage.getItem(GD_LS_DEPLOY) || 'null'); } catch (e) { /* ignore */ }
  return [
    {
      n: 1, title: 'Connect to the tenant',
      state: sameTenant && GD.conn.ok ? 'done' : (creds ? 'ready' : 'todo'),
      what: 'Enter the customer\'s cloud, vanity domain, API client ID and client secret in Tenant Configuration, then test the connection. Nothing is changed in the tenant; the tool only reads.',
      need: 'A OneAPI API client from ZIdentity (Integration > API Clients) with a ZIA role that can read DLP dictionaries, engines and rules. Ask the customer\'s Zscaler admin for these four values.',
      status: sameTenant && GD.conn.ok
        ? `Connected to ${_gdE(GD.conn.label)}: ${GD.conn.dictionaries} dictionaries, ${GD.conn.engines} engines, ${GD.conn.web_rules} web DLP rules.`
        : (creds ? 'Details entered. Test the connection before going further.' : 'Fill in the four tenant fields to begin.'),
      actions: [
        { label: 'Go to tenant details', fn: '_gdGoConfig()', kind: creds ? 'quiet' : 'primary' },
        { label: GD.testing ? 'Testing…' : 'Test connection', fn: '_gdTest()', kind: creds ? 'primary' : 'quiet', disabled: !creds || GD.testing },
      ],
    },
    {
      n: 2, title: 'Assess the tenant',
      state: assessed ? 'done' : (sameTenant && GD.conn && GD.conn.ok ? 'ready' : 'todo'),
      what: 'Runs 300+ automated checks against the tenant and produces a maturity score with a list of findings. Takes about 90 seconds. Read-only.',
      need: 'Organisation name, your name, and a scope. For a DLP engagement keep the default scopes ticked.',
      status: assessed ? 'Assessment complete. Results are below.' : 'Choose a scope and click Run Assessment.',
      actions: [{ label: 'Run assessment', fn: '_gdRun()', kind: 'primary', disabled: !creds }],
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
      n: 4, title: 'Close the gaps with a policy pack',
      state: deployed ? 'done' : (assessed || (sameTenant && GD.conn && GD.conn.ok) ? 'ready' : 'todo'),
      what: 'A policy pack is a ready-made set of DLP dictionaries, engines and rules for a regulation or a best practice. Deploy Studio checks the pack against the tenant first and shows exactly what would be created before you approve anything. Every rule ships disabled, so deploying never affects users.',
      need: 'The server must be started with START_Zscaler_Assessment_WRITES_ENABLED.bat to actually write. In read-only mode you can still run the preflight and show the customer the plan.',
      status: deployed ? `Last deployment ${_gdE(deployed.status)} on ${_gdE(deployed.at)}: ${deployed.created || 0} created, ${deployed.restored || 0} restored.` : 'Open Deploy Policy Packs, pick a pack, run preflight, review, approve.',
      actions: [{ label: 'Open Deploy Policy Packs', fn: 'openDlpPacksModal()', kind: 'primary' }],
    },
  ];
}

// ── Rendering ──────────────────────────────────────────────────────
function _gdRender() {
  const host = document.getElementById('gdPanel');
  if (!host) return;
  const steps = _gdSteps();
  const doneCount = steps.filter(s => s.state === 'done').length;
  host.innerHTML = `
    <div class="gd-head">
      <div>
        <div class="gd-eyebrow">Start here</div>
        <h2 class="gd-title">Four steps from "unknown tenant" to "gaps closed"</h2>
        <p class="gd-sub">Follow the steps in order. Each one explains what it does, what you need, and what to click. Nothing is written to the customer's tenant until step 4, and only after you approve a plan.</p>
      </div>
      <div class="gd-controls">
        <label class="gd-switch" title="Guided mode hides the advanced tools (rule migration, bypass inventory, efficacy scoring, update checks) so only the four steps are on screen.">
          <input type="checkbox" ${GD.mode === 'guided' ? 'checked' : ''} onchange="_gdSetMode(this.checked ? 'guided' : 'advanced')" aria-label="Guided mode">
          <span class="track"><span class="knob"></span></span><span class="lbl">Guided mode</span>
        </label>
        <button type="button" class="gd-btn quiet" onclick="_gdHelp(true)">? Help &amp; glossary</button>
      </div>
    </div>
    <div class="gd-progress" aria-label="${doneCount} of 4 steps done"><div class="bar" style="width:${(doneCount / 4) * 100}%"></div></div>
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
  if (!btn) return;
  if (btn.disabled) { alert('Run Assessment is disabled: an assessment is already running.'); return; }
  btn.scrollIntoView({ behavior: 'smooth', block: 'center' });
  btn.click();
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
const GD_ADVANCED_HEADINGS = ['Compliance Coverage', 'Inline DLP Rule Migration'];
const GD_ADVANCED_BUTTONS = ['openUpdateModal()', 'openBypassModal()', 'openDlpEfficacyModal()'];
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
  ['Read-only vs writes enabled', 'START_Zscaler_Assessment.bat runs read-only: assessment, preflight and journey checks all work, deploying does not. START_Zscaler_Assessment_WRITES_ENABLED.bat allows deploys. Use read-only when you only want to show the customer the plan.'],
  ['OneAPI credentials', 'The client ID and secret of an API client created in ZIdentity, plus the vanity domain (the short name in the login URL, acme for acme.zslogin.net) and the cloud (Production for almost everyone).'],
  ['Terraform export', 'The same plan as a Terraform workspace for the official zscaler/zia provider, for customers whose platform team manages Zscaler as code. Existing objects are imported, so the first plan shows exactly the gap.'],
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
      <h3>Glossary</h3>
      <dl>${GD_GLOSSARY.map(([t, d2]) => `<dt>${_gdE(t)}</dt><dd>${_gdE(d2)}</dd>`).join('')}</dl>
      <h3>If something goes wrong</h3>
      <ul>
        <li><strong>"Could not connect"</strong> under step 1 tells you the cause and the fix. Nine times out of ten it is a pasted secret that was not the real secret, or a machine behind TLS inspection.</li>
        <li><strong>"0 endpoints probed" or empty results</strong>: the credentials were rejected; test the connection.</li>
        <li><strong>Preflight says blocked</strong>: read the red card. It names the object and the missing prerequisite (a predefined dictionary, an onboarded SaaS tenant, a licensed feature).</li>
        <li><strong>"Write actions require ENABLE_WRITE_ACTIONS"</strong>: you are in read-only mode. Close the server window and start it with START_Zscaler_Assessment_WRITES_ENABLED.bat.</li>
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
  const stages = (j.stages || []).map(s => `<li><b>${E(s.name)}</b> — ${E(s.what)}</li>`).join('');
  const rows = (j.baselines || []).map(b => `<div class="dz-journey ${b.state === 'governed' ? 'ok' : (b.state === 'blocked' ? 'fail' : (b.state === 'not_started' ? 'info' : 'warn'))}"><h3>${E(b.name)}${b.version ? ` <span class="gd-dim">v${E(b.version)}</span>` : ''}</h3>${typeof _dzJourneyRowHtml === 'function' ? _dzJourneyRowHtml(b, { max: 6 }) : `Stage ${b.stage} of 5 (${E(b.stage_name)})`}</div>`).join('');
  const overall = { not_started: 'Not started: none of the baselines has been deployed yet.', in_progress: 'In progress: baselines are deployed but not yet fully enabled and enforcing.', governed: 'Governed: every baseline is deployed, enabled and enforcing.', blocked: 'Blocked: something a baseline needs is missing from the tenant.' }[j.status] || j.status;
  card.innerHTML = `
    <h2>Data governance journey</h2>
    <p class="gd-sub">Where this tenant stands against each baseline pack, measured read-only during the assessment. <strong>${E(overall)}</strong> Overall stage ${j.stage || 0} of 5, ${j.score || 0}% of the way. Deploying a baseline (Deploy Studio) creates what is missing and keeps everything the customer already has; enabling and hardening rules in the ZIA portal moves the tenant up the ladder.</p>
    <details class="dz-fold"><summary>The five stages</summary><ol class="dz-next">${stages}</ol></details>
    ${rows || '<p class="gd-sub">No baseline packs are installed.</p>'}`;
}
(function () {
  const orig = window.showResults;
  if (typeof orig !== 'function') return;
  window.showResults = function (data) {
    orig.apply(this, arguments);
    try { _gdJourneyCard(data && data.journey); } catch (e) { console.warn('journey card', e); }
  };
})();

// ── Boot ───────────────────────────────────────────────────────────
(function () {
  const anchor = document.getElementById('stepBar');
  if (!anchor) return;
  _gdLoad();
  const panel = document.createElement('section');
  panel.id = 'gdPanel'; panel.className = 'gd-panel'; panel.setAttribute('aria-label', 'Start here');
  anchor.insertAdjacentElement('afterend', panel);
  _gdApplyMode();
  _gdRender();
  // Keep the step chips honest as the operator types, runs, and deploys.
  ['vd', 'cid', 'csec', 'cloud'].forEach(id => { const el = document.getElementById(id); if (el) el.addEventListener('input', _gdRender); });
  GD.timer = setInterval(_gdRender, 2500);
  const fab = document.createElement('button');
  fab.type = 'button'; fab.id = 'gdHelpFab'; fab.className = 'gd-btn primary'; fab.textContent = '? Help';
  fab.setAttribute('aria-label', 'Open help and glossary'); fab.onclick = () => _gdHelp(true);
  document.body.appendChild(fab);
})();
