// ── Policy Pack Deploy Studio ────────────────────────────────────
// Select packs → preflight against the live tenant → review the exact
// plan, warnings and impacts → give explicit consent → deploy.
// State lives in DZ; every step re-renders from it.

const DZ = {
  packs: [], selected: new Set(), details: {}, open: new Set(), journey: {}, write: null,
  options: { use_rank_0: false, apply_tweaks: true },
  channels: {},            // pack id -> DLP channels to deploy into (web/endpoint/saas/email)
  deployments: null, undoBusy: null, undoResult: null,
  step: 1, report: null, result: null, busy: false, consent: false, error: '',
};
const DZ_STEPS = ['Select packs', 'Preflight', 'Approve', 'Deploy'];
// Every status carries a plain-language explanation (shown as a tooltip on
// the status chip) so a first-time operator can read a plan without help.
const DZ_STATUS = {
  create:             { label: 'Will create',     cls: 'st-create',  icon: '+', help: 'This object does not exist in the tenant yet. Deploying creates it exactly as the pack defines it.' },
  modify:             { label: 'Will modify',     cls: 'st-modify',  icon: '✎', help: 'An existing tenant object will be changed (a confidence tweak). The change is listed so you can approve it.' },
  restore:            { label: 'Will overwrite',  cls: 'st-modify',  icon: '↺', help: 'Converge mode only: this policy pack object was changed in the tenant and you asked for it to be reset to the policy pack definition.' },
  reuse:              { label: 'Already present', cls: 'st-reuse',   icon: '✓', help: 'The tenant already has this object; its content matched where the tenant let it be compared (the row says when it could not be). Nothing is written; the pack simply uses it.' },
  reuse_differs:      { label: 'Kept as-is',      cls: 'st-differs', icon: '≠', help: 'The tenant has an object with this name but different content (for a policy pack: the customer customized it, for example enabled the rule or hardened its action). The tenant version is kept and used; the pack version is not applied.' },
  conflict:           { label: 'Conflict',        cls: 'st-blocked', icon: '!', help: 'Two selected packs define this name differently, or it clashes with a predefined Zscaler object. Deselect one pack or rename it.' },
  blocked_dependency: { label: 'Skipped: needs a prerequisite', cls: 'st-blocked', icon: '–', help: 'Something this object needs is missing (a dictionary, an engine, an onboarded SaaS tenant, a licensed feature). It will not be created until that exists.' },
  skip_empty:         { label: 'Skipped: empty',  cls: 'st-blocked', icon: '–', help: 'This dictionary has no phrases or patterns, so it could never match anything and is not created.' },
  noop:               { label: 'No change',       cls: 'st-reuse',   icon: '✓', help: 'The tweak\'s target is already at the desired value.' },
  // apply results
  created:  { label: 'Created',  cls: 'st-ok',      icon: '✓', help: 'Created in the tenant. It becomes active for users only after ZIA activation.' },
  modified: { label: 'Modified', cls: 'st-ok',      icon: '✓', help: 'The existing object was changed as planned.' },
  restored: { label: 'Overwritten', cls: 'st-ok',   icon: '↺', help: 'Converge mode: the object was reset to the policy pack definition.' },
  reused:   { label: 'Reused',   cls: 'st-reuse',   icon: '✓', help: 'Already existed; nothing was written.' },
  skipped:  { label: 'Skipped',  cls: 'st-blocked', icon: '–', help: 'Not written, for the reason shown.' },
  failed:   { label: 'Failed',   cls: 'st-blocked', icon: '✕', help: 'The API refused this write. The error text is shown; other objects were not affected.' },
};
const DZ_KIND = { dictionary: 'Dictionary', engine: 'Engine', app_group: 'App group', policy: 'Policy', tweak: 'Tweak', resource: 'Prerequisite', template: 'Template' };
const DZ_KIND_PLURAL = { dictionary: ['dictionary', 'dictionaries'], engine: ['engine'], app_group: ['app group'], policy: ['rule'], tweak: ['tweak'] };
const DZ_KIND_HELP = {
  dictionary: 'What to look for: phrases and/or patterns (for example "MRN" near a 7-digit number).',
  engine: 'How dictionaries combine into a decision with AND / OR and match counts. Rules point at engines.',
  policy: 'Where and how an engine is enforced: which traffic, which users, and the action (ALLOW = monitor, BLOCK = stop).',
  tweak: 'A change to the confidence level of a dictionary that already exists in the tenant.',
  app_group: 'An Endpoint DLP application group: desktop applications (by Zscaler catalogue ID) that endpoint rules can be scoped to, for example the ChatGPT and Claude desktop apps.',
  resource: 'Something the tenant must already have (an onboarded SaaS tenant, a notification template, a label).',
  template: 'A predefined Zscaler dictionary that a pack dictionary is cloned from.',
};
const DZ_CHANNEL_HELP = {
  web: 'Inline web DLP: uploads through the Zscaler cloud (browsers, apps).',
  endpoint: 'Endpoint DLP: files moving off managed devices (USB, printing, network shares, app access) via Zscaler Client Connector.',
  saas: 'SaaS Security API: data already at rest in onboarded SaaS tenants (Box, Google Drive, Slack…), scanned out of band.',
  email: 'Outbound email DLP for onboarded Microsoft 365 / Gmail tenants.',
  cloud_app: 'Cloud App Control: per-application actions (allow view, block upload/share/send) for a category such as File Sharing, Webmail or AI & ML. Runs before DLP.',
  file_type: 'File Type Control: allow, caution or block uploads/downloads of file categories (spreadsheets, archives, images). Runs before DLP.',
  url: 'URL Filtering: allow, caution, block or isolate by URL category, protocol and request method. Runs before DLP.',
  ssl: 'SSL Inspection: decrypt, do not decrypt, or block TLS traffic for applications or categories. Without decryption, DLP cannot inspect HTTPS uploads.',
};
// Rule channels: which ZIA policy a pack rule lands in.
const DZ_CHANNEL = { web: 'Web', endpoint: 'Endpoint', saas: 'SaaS', email: 'Email',
                     cloud_app: 'Cloud App Control', file_type: 'File Type Control', url: 'URL Filtering', ssl: 'SSL Inspection' };
const _dzChan = c => DZ_CHANNEL[c] || (c ? String(c) : '');
// Containment channels a pack never deploys: they are carved out and
// managed separately (kept in step with pack_channels.CARVED_CHANNELS).
const DZ_CARVED = ['cloud_app', 'file_type', 'url', 'ssl'];
// Shown in large bold type on every pack card; a pack.json deploy_note
// replaces it. One channel per run keeps each deploy small and checkable.
const DZ_ONE_CHANNEL_NOTE = "Install one channel at a time. Deploy Web DLP first, check it, then Endpoint DLP, then SaaS, then Email, one channel per run. A small run is easy to verify and avoids the burst of requests that makes ZIA block the API client (Resource Access Blocked).";

function _dzChannelChips(channels) {
  if (!channels) return '';
  const chips = Object.keys(DZ_CHANNEL).filter(c => c !== 'web' && !DZ_CARVED.includes(c) && channels[c])
    .map(c => `<span class="dz-chip kind-channel" title="${_dzChan(c)} rules">${channels[c]} ${_dzChan(c)}</span>`).join('');
  const carved = DZ_CARVED.filter(c => channels[c]).map(_dzChan);
  const note = carved.length ? `<span class="dz-chip kind-muted" title="Packs deploy detection only. ${carved.join(', ')} rules in this pack are not deployed; manage containment separately.">${carved.join(' · ')} carved out</span>` : '';
  return chips + note;
}

// ── Channel targets ───────────────────────────────────────────────
// Which DLP channels a pack is deployed into. Default: the channels the
// pack ships rules for. A ticked channel the pack has no rule for gets
// monitor-only extension rules carrying the pack's engines, one disabled
// rule per engine (Endpoint DLP on removable media; ZIA allows at most
// four engines per endpoint rule) — the same shape as every shipped pack;
// an unticked channel is skipped. Containment rules (Cloud App Control,
// File Type, URL, SSL) are not part of the choice.
const DZ_DLP = ['web', 'endpoint', 'saas', 'email'];
const DZ_DLP_LABEL = { web: 'Inline Web DLP', endpoint: 'Endpoint DLP', saas: 'SaaS Security', email: 'Outbound Email DLP' };
// The channel choice lives for this page only. It used to be remembered
// in the browser across sessions, and a choice made weeks ago (Web only)
// silently dropped 51 Endpoint, SaaS and Email rules from a Fed pack
// deploy. Every time Deploy policy packs opens, every channel the pack
// ships rules for is ticked; unticking is a per-deploy decision.
const DZ_LS_CHANNELS = 'zassess_pack_channels';   // the old key, cleared so a stale choice can never come back
function _dzLoadChannels() {
  DZ.channels = {};
  try { localStorage.removeItem(DZ_LS_CHANNELS); } catch (e) { /* storage unavailable */ }
}
function _dzSaveChannels() { /* kept in memory only (DZ.channels); see above */ }
function _dzDefaultChannels(p) { return DZ_DLP.filter(c => (p.channels || {})[c]); }
// A choice made on this page is only trusted while the pack still ships
// rules on the same channels it did when the choice was made.
function _dzChannelsFor(id) {
  const p = DZ.packs.find(x => x.id === id);
  if (!p) return [];
  const saved = DZ.channels[id];
  const packed = _dzDefaultChannels(p).join(',');
  if (!saved || typeof saved !== 'object' || Array.isArray(saved) || saved.packed !== packed) return _dzDefaultChannels(p);
  return (saved.on || []).filter(c => DZ_DLP.includes(c));
}
function _dzSetChannel(id, ch, on) {
  const p = DZ.packs.find(x => x.id === id);
  const cur = new Set(_dzChannelsFor(id));
  if (on) cur.add(ch); else cur.delete(ch);
  DZ.channels[id] = { on: DZ_DLP.filter(c => cur.has(c)), packed: p ? _dzDefaultChannels(p).join(',') : '' };
  _dzSaveChannels();
  _dzRenderSelect();
}
function _dzTargets(ids) {
  const out = {};
  for (const id of ids) out[id] = _dzChannelsFor(id);
  return out;
}
function _dzChannelsHtml(p) {
  const chosen = new Set(_dzChannelsFor(p.id));
  const has = c => (p.channels || {})[c] || 0;
  const engines = p.engines || 0;
  const boxes = DZ_DLP.map(c => {
    const n = has(c);
    const disabled = !n && !engines;
    const hint = n ? `${_dzN(n, 'rule')} in the pack` : (engines ? `adds a monitor-only rule with the pack's ${_dzN(engines, 'engine')}` : 'no engines in this pack to put here');
    return `<label class="dz-chan ${chosen.has(c) ? 'on' : ''} ${disabled ? 'off' : ''}" title="${_dzE(DZ_CHANNEL_HELP[c] || '')}" onclick="event.stopPropagation()">
      <input type="checkbox" ${chosen.has(c) ? 'checked' : ''} ${disabled ? 'disabled' : ''} onchange="_dzSetChannel('${_dzE(p.id)}', '${c}', this.checked)" aria-label="${_dzE(DZ_DLP_LABEL[c])}">
      <span class="nm">${_dzE(DZ_DLP_LABEL[c])}</span><span class="hint">${_dzE(hint)}</span></label>`;
  }).join('');
  const added = DZ_DLP.filter(c => chosen.has(c) && !has(c) && engines).length;
  const skippedCh = DZ_DLP.filter(c => !chosen.has(c) && has(c));
  const skippedRules = skippedCh.reduce((n, c) => n + has(c), 0);
  return `<div class="dz-channels" onclick="event.stopPropagation()">
    <div class="dz-channels-h">Deploy the engines into <span class="d">${added ? `· ${_dzN(added, 'channel')} added with a monitor rule` : ''}</span></div>
    <div class="dz-chans">${boxes}</div>
    ${skippedCh.length ? `<div class="dz-chan-warn" role="status">⚠ ${_dzE(skippedCh.map(c => DZ_DLP_LABEL[c]).join(', '))} ${skippedCh.length === 1 ? 'is' : 'are'} unticked: the ${_dzN(skippedRules, 'rule')} this pack ships there will NOT be deployed. Tick the channel to deploy them.</div>` : ''}</div>`;
}
function _dzTargetsSummary(ids) {
  return ids.map(id => {
    const p = DZ.packs.find(x => x.id === id) || { id };
    const ch = _dzChannelsFor(id);
    return `${_dzE(p.name || id)}: ${ch.length ? ch.map(c => _dzE(DZ_DLP_LABEL[c])).join(', ') : 'containment rules only'}`;
  }).join(' · ');
}

function _dzCreds() {
  // The assessor's name goes with every pack request: a deploy names only
  // the assessor in the provenance tag and the deployment record.
  const v = id => (document.getElementById(id) || {}).value || '';
  if (typeof migrateCredBody === 'function') {
    const b = migrateCredBody(); delete b.customer_id; b.assessor = v('assessor').trim(); return b;
  }
  return { cloud: v('cloud') || 'production', vanity_domain: v('vd'), client_id: v('cid'), client_secret: v('csec'),
           auth_method: v('authMethod') === 'legacy' ? 'legacy' : 'oneapi', username: v('zuser'), password: v('zpass'), api_key: v('zkey'),
           assessor: v('assessor').trim() };
}
// What is in scope on the Scope page: the rule picker and Export from tenant
// read only the DLP channels marked Zscaler there (user rule 1).
function _dzScope() {
  try { return (typeof scopePageSelection === 'function') ? scopePageSelection() : {}; } catch (e) { return {}; }
}
// The ticked scopes go with the preflight, the deploy and an approval request:
// with ZIA platform ticked the plan reads Admin Ranking, so each new rule takes
// the admin rank it needs (not rank 7). The same list each time, or the plan changes.
function _dzRankScopes() { const s = _dzScope().scopes; return Array.isArray(s) ? s : []; }
const _dzE = s => escapeHtml(String(s == null ? '' : s));
// A pack push (deploy or Terraform hand-off) names the assessor in every
// object it creates, never Zscaler Made Easy, so it needs the name first.
const DZ_ASSESSOR_REQUIRED = "Enter the assessor's name (Scope assessment → Assessor name) before pushing a policy pack. Every object a pack creates names the assessor in its description, never Zscaler Made Easy.";
const DZ_ASSESSOR_NOT_TOOL = "The assessor's name must name the person who assesses and deploys the pack, not the tool (no \"Zscaler Made Easy\" in any spelling): it is part of every pushed object's description.";
function _dzNeedAssessor() {
  const who = String((_dzCreds() || {}).assessor || '').trim();
  // Same rule as the server and the Terraform CLI (pack_deploy.TOOL_NAME_PATTERN).
  if (/dlp[\W_]*check|zscaler[\W_]*made[\W_]*easy/i.test(who)) throw new Error(DZ_ASSESSOR_NOT_TOOL);
  if (who) return;
  throw new Error(DZ_ASSESSOR_REQUIRED);
}
const _dzN = (n, one, many) => `${n} ${n === 1 ? one : (many || one + 's')}`;

function _ensureDlpPacksModal() {
  if (document.getElementById('dlpDeployModal')) return;
  const m = document.createElement('div');
  m.id = 'dlpDeployModal';
  m.setAttribute('role', 'dialog');
  m.setAttribute('aria-modal', 'true');
  m.setAttribute('aria-labelledby', 'dzTitle');
  m.innerHTML = `
    <div class="dz-sheet">
      <div class="dz-head">
        <div>
          <h2 id="dzTitle">Deploy policy packs</h2>
          <p class="dz-sub" id="dzSub">Pick the packs to deploy. Everything is cross-checked against your tenant before anything is written.</p>
          <a class="dz-link dz-howto" id="dzHowTo" href="/report/deploy-flow" target="_blank" rel="noopener" title="Opens a step-by-step walk-through of what a deployment and a removal do, in a new tab.">How a deployment works</a>
        </div>
        <button type="button" class="dz-close" onclick="closeDlpPacksModal()" aria-label="Close">✕</button>
      </div>
      <nav class="dz-steps" id="dzSteps" aria-label="Deployment steps"></nav>
      <div class="dz-body" id="dzBody" aria-live="polite"></div>
      <footer class="dz-foot" id="dzFoot"></footer>
    </div>`;
  document.body.appendChild(m);
  m.addEventListener('click', (e) => { if (e.target === m && !DZ.busy) closeDlpPacksModal(); });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && m.classList.contains('is-open') && !DZ.busy) closeDlpPacksModal();
  });
}

async function openDlpPacksModal() {
  _ensureDlpPacksModal();
  DZ._opener = document.activeElement;   // focus returns there when the Studio closes
  const m = document.getElementById('dlpDeployModal');
  m.classList.add('is-open');
  document.body.style.overflow = 'hidden';
  DZ.step = 1; DZ.report = null; DZ.result = null; DZ.consent = false; DZ.error = ''; DZ.removal = null; DZ.exportPack = null;
  _dzLoadChannels();
  _dzRender();
  _dzLoadWriteMode();
  _dzLoadDeployments();
  try {
    const r = await fetch('/api/dlp-packs', { cache: 'no-store' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    DZ.packs = (await r.json()).packs || [];
    // Drop selections for packs that no longer exist.
    DZ.selected = new Set([...DZ.selected].filter(id => DZ.packs.some(p => p.id === id)));
    // The tenant profile's industry (or its ticked packs) pre-selects the packs; the operator adds or drops from there.
    _dzAutoSelectFromScope();
  } catch (e) {
    DZ.packs = []; DZ.error = `Couldn't load packs: ${e.message}`;
  }
  _dzRender();
  const first = m.querySelector('.dz-pack input, .dz-close');
  if (first) first.focus();
}

// ── Write mode ────────────────────────────────────────────────────
// Deploys are refused unless the server is in write mode. It comes from
// the start script (ENABLE_WRITE_ACTIONS) or from this switch, which only
// works while the server is bound to localhost and needs the phrase typed.
async function _dzLoadWriteMode() {
  try {
    const r = await fetch('/api/write-mode', { cache: 'no-store' });
    DZ.write = r.ok ? await r.json() : null;
  } catch (e) { DZ.write = null; }
  if (DZ.step === 1 || DZ.step === 3) _dzRender();
}
// The app-wide safety banner (safety_banner.js) can switch back to read-only,
// or notice another tab did: re-read write mode so this sheet agrees with it.
window.addEventListener('dlp:write-mode', e => {
  if (!e || !e.detail || e.detail.from !== 'banner') return;
  if (!document.getElementById('dzTitle')) return;   // the Studio was never opened on this page
  DZ.writeNote = '';
  _dzLoadWriteMode();
});
// The switch asks in the app's own dialog (ui_auth.js): never the browser's
// prompt() / alert() / confirm(), which an embedded browser may refuse
// silently, so that clicking Enable write mode looked as if nothing happened.
// What happened, and why the server refused if it did, is written into the
// banner itself as well as announced.
const _dzDlg = () => window.dlpDialog || null;
async function _dzSetWriteMode(enable) {
  const w = DZ.write || {};
  const dlg = _dzDlg();
  let confirm = '';
  DZ.writeNote = '';
  if (enable) {
    if (!w.can_toggle) {
      DZ.writeNote = w.reason || 'Write mode can only be enabled from the start script on this server.';
      if (dlg) await dlg.notice({ title: 'Write mode cannot be enabled from here', body: DZ.writeNote, tone: 'bad' });
      _dzRender(); return;
    }
    const expected = w.confirm_phrase || 'YES_I_UNDERSTAND';
    const body = `It applies to every browser and tab using this server, and stays on until the server restarts (there is a Back to read-only button).\n\nWith write mode on, this app can create and delete DLP policy in the tenant you are signed in to. Deploy policy packs creates the rules, engines, dictionaries and application groups you approve: every rule arrives DISABLED and existing objects are not overwritten (with confidence tweaks on, the confidence of dictionaries a pack tunes is modified, and each such change is listed as Will modify for your approval). The removal review and Undo delete the objects you pick, after their own confirmation.`;
    if (dlg) {
      confirm = await dlg.phrase({ title: 'Enable write mode on this server?', body, phrase: expected, okLabel: 'Enable write mode' });
    } else {
      try { confirm = window.prompt(`Enable write mode on this server?\n\n${body}\n\nType ${expected} to continue:`, ''); } catch (e) { confirm = null; }
    }
    if (!confirm) {
      DZ.writeNote = 'Still read-only: no confirmation phrase was entered.' + (dlg ? '' : ' If no box appeared, this browser cannot show prompts; ' + ((DZ.write || {}).how_to_enable || 'start the server with ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND') + ' instead.');
      announce(DZ.writeNote); _dzRender(); return;
    }
  } else {
    let ok = false;
    const q = { title: 'Switch back to read-only?', body: 'Preflight and the journey check keep working; deploying will be refused until write mode is enabled again.', okLabel: 'Back to read-only' };
    if (dlg) ok = await dlg.ask(q);
    else { try { ok = window.confirm(`${q.title}\n\n${q.body}`); } catch (e) { ok = false; } }
    if (!ok) return;
  }
  try {
    const r = await fetch('/api/write-mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enable, confirm }) });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((data.detail && (data.detail.cause || data.detail)) || `HTTP ${r.status}`);
    DZ.write = data;
    announce(data.enabled ? 'Write mode enabled on this server until it restarts.' : 'Read-only mode.');
    // Every page's safety banner shows (or hides) its write-mode warning now, not at its next poll.
    try { window.dispatchEvent(new CustomEvent('dlp:write-mode', { detail: { from: 'studio', status: data } })); } catch (e) { /* old browser */ }
    // The removal review is open: refresh it so Remove now unlocks in place.
    if (DZ.removal && document.getElementById('rmConsent')) { _dzRemovalRender(); return; }
    // A plan made in read-only mode carries a read-only blocker; refresh it.
    if (DZ.report && DZ.step >= 2) { _dzRunPreflight(); return; }
  } catch (e) {
    DZ.writeNote = `Could not change write mode: ${e.message}`;
    announce(DZ.writeNote);
    if (dlg) await dlg.notice({ title: 'Could not change write mode', body: String(e.message || e), fix: 'The server answered above. A wrong phrase or a server bound beyond localhost is refused; to enable writes at start instead, ' + ((DZ.write || {}).how_to_enable || 'start it with ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND') + '.', tone: 'bad' });
  }
  _dzRender();
}
function _dzWriteBanner() {
  const w = DZ.write;
  if (!w) return '';
  const note = DZ.writeNote ? `<div class="d dz-write-note" role="status">${_dzE(DZ.writeNote)}</div>` : '';
  if (w.enabled) {
    return `<div class="dz-write on"><span class="dz-status warnings">Write mode</span><div><div class="t">Deploying will create objects in the tenant you approve; the removal review and Undo can delete them.</div>
      <div class="d">This app can now create and delete DLP policy in the tenant you are signed in to. Every rule arrives DISABLED; existing objects are not overwritten (confidence tweaks on existing dictionaries are listed as <em>Will modify</em> for approval). ${w.source === 'session' ? 'Enabled from this app: it applies to every browser using this server until the server restarts, or until you click Back to read-only.' : 'Set by the start script (ENABLE_WRITE_ACTIONS); on until the server restarts.'}</div>${note}</div>
      ${w.source === 'session' ? `<button type="button" class="dz-btn" onclick="_dzSetWriteMode(false)">Back to read-only</button>` : ''}</div>`;
  }
  return `<div class="dz-write off"><span class="dz-status warnings">Read-only</span><div><div class="t">Preflight, the plan and the journey check work; deploying is refused.</div>
    <div class="d">${w.can_toggle ? 'Write mode lets this app create and delete DLP policy in the tenant you are signed in to. Enable it here when the customer has agreed to the plan; you will be asked to type a confirmation phrase in a box on this page.' : _dzE(w.reason || '')}</div>${note}</div>
    ${w.can_toggle ? `<button type="button" class="dz-btn primary" onclick="_dzSetWriteMode(true)">Enable write mode</button>` : ''}</div>`;
}

function closeDlpPacksModal() {
  const m = document.getElementById('dlpDeployModal');
  if (!m) return;
  m.classList.remove('is-open');
  document.body.style.overflow = '';
  const o = DZ._opener; DZ._opener = null;
  if (o && document.body.contains(o) && typeof o.focus === 'function') o.focus();
}

function _dzRender() {
  if (DZ.removal) return _dzRemovalRender();
  if (DZ.exportPack) return _dzExportRender();
  // The sheet's chrome is the deploy wizard's again (a removal renames it while it runs).
  document.getElementById('dzTitle').textContent = 'Deploy policy packs';
  const steps = document.getElementById('dzSteps');
  steps.setAttribute('aria-label', 'Deployment steps');
  steps.innerHTML = DZ_STEPS.map((s, i) => {
    const n = i + 1;
    const cls = n === DZ.step ? 'is-active' : (n < DZ.step ? 'is-done' : '');
    return `<div class="dz-step ${cls}" ${n === DZ.step ? 'aria-current="step"' : ''}><span class="n">${n < DZ.step ? '✓' : n}</span>${s}</div>`;
  }).join('');
  const subs = {
    1: 'Pick the packs to deploy. Everything is cross-checked against your tenant before anything is written.',
    2: 'Reading the tenant and cross-referencing dependencies, overlaps and impact. Nothing has been written.',
    3: 'This is exactly what will happen. Deployment starts only after you approve.',
    4: DZ.busy ? 'Deploying — please keep this window open.' : 'Deployment finished.',
  };
  document.getElementById('dzSub').textContent = subs[DZ.step];
  ({ 1: _dzRenderSelect, 2: _dzRenderReview, 3: _dzRenderApprove, 4: _dzRenderDeploy })[DZ.step]();
}

// ── Pre-selection from the tenant profile ────────────────────────
// The profile's industry (or the packs ticked on the profile) decides the
// packs Deploy policy packs starts with: they are ticked when the sheet
// opens and again whenever the scope changes (another industry chosen,
// packs ticked on the profile). What the operator changes by hand after
// that is theirs: a cleared or widened selection stays as it is until the
// scope itself changes.
function _dzScopeKey(sc) { return sc && sc.scoped ? `${sc.industry}|${sc.packs_from}|${(sc.packs || []).join(',')}` : ''; }
function _dzAutoSelectFromScope() {
  const sc = (window.GD && GD.scope && GD.scope.scoped) ? GD.scope : null;
  if (!sc || !Array.isArray(DZ.packs) || !DZ.packs.length) return false;
  const key = _dzScopeKey(sc);
  if (DZ.autoKey === key) return false;   // this scope already had its turn; the operator's changes stand
  const want = (sc.packs || []).filter(id => DZ.packs.some(p => p.id === id));
  DZ.selected = new Set(want);
  DZ.autoSelected = new Set(want);
  DZ.autoKey = key;
  DZ.autoIndustry = sc.industry;
  DZ.autoFrom = sc.packs_from;
  return true;
}
function _dzAutoNoteHtml() {
  const sc = (window.GD && GD.scope && GD.scope.scoped) ? GD.scope : null;
  if (!sc || !DZ.autoSelected || !DZ.autoSelected.size) return '';
  const names = id => ((DZ.packs.find(p => p.id === id) || {}).name || id);
  const still = [...DZ.autoSelected].filter(id => DZ.selected.has(id));
  const added = [...DZ.selected].filter(id => !DZ.autoSelected.has(id));
  const dropped = [...DZ.autoSelected].filter(id => !DZ.selected.has(id));
  return `<div class="dz-card sev-info"><div class="bar"></div><div><div class="t">Pre-selected for ${_dzE(sc.industry)}${DZ.autoFrom === 'profile' ? ' (the packs ticked on the tenant profile)' : ' (the industry\'s packs from the tenant profile)'}: ${_dzE([...DZ.autoSelected].map(names).join(', '))}</div>
    <div class="d">Tick more packs to add them, or untick any; the selection is yours from here.${added.length ? ` Added by you: ${_dzE(added.map(names).join(', '))}.` : ''}${dropped.length ? ` Dropped by you: ${_dzE(dropped.map(names).join(', '))}.` : ''}${!still.length && !added.length ? ' Nothing is selected now.' : ''}</div></div></div>`;
}

// ── Step 1: select ────────────────────────────────────────────────
function _dzRenderSelect() {
  const body = document.getElementById('dzBody');
  if (!body) return;   // Deploy policy packs is not open (the hand-off page and the pack cards call this on their own)
  if (DZ.error && !DZ.packs.length) {
    body.innerHTML = `<div class="dz-card sev-error"><div class="bar"></div><div><div class="t">Something went wrong</div><div class="d">${_dzE(DZ.error)}</div></div></div>`;
  } else if (!DZ.packs.length) {
    body.innerHTML = `<div class="dz-empty">No policy packs found.<br><span style="font-size:0.8rem;">Drop a folder with <code>configs/dlp_*.json</code> in the project root, or see POLICY_PACKS.md.</span></div>`;
  } else {
    const scope = (window.GD && GD.scope && GD.scope.scoped) ? GD.scope : null;
    const inScope = p => !scope || scope.packs.includes(p.id) || DZ.selected.has(p.id);
    const ordered = scope ? [...DZ.packs].sort((a, b) => (inScope(a) ? 0 : 1) - (inScope(b) ? 0 : 1)) : DZ.packs;
    const cards = ordered.map(p => {
      const sel = DZ.selected.has(p.id);
      const foldable = scope && !inScope(p) && !DZ.showAllPacks;
      if (foldable) return '';
      const scopeChip = scope && scope.packs.includes(p.id) ? `<span class="dz-chip kind-baseline" title="Recommended for ${_dzE(scope.industry)}">For ${_dzE(scope.industry)}</span>` : '';
      const det = DZ.open.has(p.id) ? _dzDetailHtml(p.id) : '';
      return `
      <div class="dz-pack ${sel ? 'is-selected' : ''}" role="group" aria-label="${_dzE(p.name || p.id)}" onclick="_dzCardClick(event, '${_dzE(p.id)}')">
        <div class="dz-pack-top">
          <h3>${_dzE(p.name || p.id)}${p.version ? `<span class="v">v${_dzE(p.version)}</span>` : ''} ${scopeChip}</h3>
          <label class="dz-switch" title="${sel ? 'Deselect' : 'Select'} ${_dzE(p.name || p.id)}" onclick="event.stopPropagation()">
            <input type="checkbox" ${sel ? 'checked' : ''} onchange="_dzTogglePack('${_dzE(p.id)}', this.checked)" aria-label="Select ${_dzE(p.name || p.id)}">
            <span class="track"><span class="knob"></span></span>
          </label>
        </div>
        <div class="dz-deploy-note" role="note">${_dzE(p.deploy_note || DZ_ONE_CHANNEL_NOTE)}</div>
        ${p.rate && p.rate.text ? `<div class="dz-rate-note" role="note" title="ZIA API rate limits: dictionaries, engines and Web/SaaS/Email rules 1 a second and 400 an hour; Endpoint DLP rules, Cloud App Control rules and activations 10 a minute and 40 an hour; deletes 1 a second and 400 an hour. The preflight and the removal preview forecast against the requests sent in the last hour."><span class="k">Rate limits</span>${_dzE(p.rate.text)}</div>` : ''}
        ${p.baseline ? `<div class="dz-baseline" title="Policy pack: the reference this tenant is measured against. Deploy it into an empty (greenfield) tenant or on top of an existing (brownfield) one; whatever already exists is kept exactly as the customer has it. Afterwards, Where is this tenant? shows the stage reached and the next steps.">
          <span class="dz-chip kind-baseline">Policy pack</span>${p.baseline.prefix ? `<span class="dz-chip">prefix ${_dzE(p.baseline.prefix)}</span>` : ''}
          <span class="d">Greenfield or brownfield: creates what is missing, never overwrites. Then measures the journey.</span></div>` : ''}
        <p>${_dzE(p.description || 'No description provided.')}</p>
        ${p.audience || p.when_to_use ? `<div class="dz-fit">${p.audience ? `<div><span class="k">Who it's for</span>${_dzE(p.audience)}</div>` : ''}${p.when_to_use ? `<div><span class="k">Use it when</span>${_dzE(p.when_to_use)}</div>` : ''}</div>` : ''}
        <div class="dz-meta">
          <span class="dz-chip kind-dictionary">${_dzN(p.dictionaries || 0, 'dictionary', 'dictionaries')}</span>
          <span class="dz-chip kind-engine">${_dzN(p.engines || 0, 'engine')}</span>
          <span class="dz-chip kind-policy">${_dzN(p.policies || 0, 'policy', 'policies')}</span>
          ${_dzChannelChips(p.channels)}
        </div>
        ${_dzChannelsHtml(p)}
        <div class="dz-links">
          <button type="button" class="dz-link" onclick="event.stopPropagation(); _dzToggleDetail('${_dzE(p.id)}')">${DZ.open.has(p.id) ? 'Hide details' : 'Show details'}</button>
          ${p.baseline ? `<button type="button" class="dz-link" title="Read-only: places every object of this policy pack in the tenant (missing, deployed, monitoring, enforcing, customized) and shows the stage reached and the next steps." onclick="event.stopPropagation(); _dzJourney('${_dzE(p.id)}')">${(DZ.journey[p.id] || {}).busy ? 'Measuring…' : 'Where is this tenant?'}</button>` : ''}
          <button type="button" class="dz-link" title="Hand this pack to a platform team as a Terraform workspace (official zscaler/zia provider): what you get, how to run it, download. Opens in a new tab." onclick="event.stopPropagation(); openToolTab('terraform', '${_dzE(p.id)}')">Terraform hand-off</button>
          ${p.id === 'zbp_source_code_baseline' ? `<button type="button" class="dz-link" title="Read the tenant's own source-code dictionaries (an Anchor and a Signal per language, paired by name), preview the pairing, then rebuild this pack from them: dictionaries keep their tenant names, each language gets one engine (Signal > N AND Anchor > 0), the old pack dictionaries and engines are dropped." onclick="event.stopPropagation(); _dzFromTenant('${_dzE(p.id)}')">${(DZ.fromTenant || {}).busy ? 'Reading tenant…' : 'Rebuild from tenant dictionaries'}</button>` : ''}
        </div>
        ${p.id === 'zbp_source_code_baseline' ? _dzFromTenantHtml() : ''}
        ${det}
        ${p.baseline ? _dzJourneyHtml(p.id) : ''}
      </div>`;
    }).join('');
    body.innerHTML = `
      ${_dzWriteBanner()}
      ${_dzAutoNoteHtml()}
      <div class="dz-grid">${cards}</div>
      ${(() => { const sc = (window.GD && GD.scope && GD.scope.scoped) ? GD.scope : null; if (!sc) return ''; const hidden = DZ.packs.filter(p => !sc.packs.includes(p.id) && !DZ.selected.has(p.id)); if (!hidden.length) return ''; return `<div class="dz-scope-fold"><span class="d">Scope: ${_dzE(sc.industry)} (from the tenant profile). ${DZ.showAllPacks ? `All packs shown; ${hidden.length} are outside this vertical.` : `${hidden.length} pack(s) for other verticals are folded away: ${_dzE(hidden.map(p => p.name || p.id).join(', '))}.`}</span> <button type="button" class="dz-link" onclick="DZ.showAllPacks = !DZ.showAllPacks; _dzRenderSelect()">${DZ.showAllPacks ? 'Show only this vertical' : 'Show all packs'}</button></div>`; })()}
      <div class="dz-options">
        <div class="dz-option">
          <div><div class="t">Apply confidence tweaks</div><div class="d">Lets packs adjust confidence on existing dictionaries (e.g. Medical → Low). Each change is listed for approval.</div></div>
          <label class="dz-switch"><input type="checkbox" ${DZ.options.apply_tweaks ? 'checked' : ''} onchange="DZ.options.apply_tweaks=this.checked" aria-label="Apply confidence tweaks"><span class="track"><span class="knob"></span></span></label>
        </div>
        <div class="dz-option">
          <div><div class="t">Rank 0 (override rule ordering)</div><div class="d">New rules take precedence over rules made by lower-ranked admins. Only for resolving ordering conflicts.</div></div>
          <label class="dz-switch"><input type="checkbox" ${DZ.options.use_rank_0 ? 'checked' : ''} onchange="DZ.options.use_rank_0=this.checked" aria-label="Use rank 0"><span class="track"><span class="knob"></span></span></label>
        </div>
        <div class="dz-option">
          <div><div class="t">Remove rules from this tenant</div><div class="d">The one way to remove: lists every DLP rule in the tenant on every channel — with its state, its engines and whether Zscaler Made Easy created it — and you tick the ones to remove (filters select a pack's rules in one click). The check that follows removes only those rules, plus each engine and dictionary that nothing else uses; anything another rule or engine still uses is kept and named. You approve the exact list, confirm once more, the usage is checked again right before each engine or dictionary goes, and a fresh read verifies the result. Needs write mode.</div></div>
          <button type="button" class="dz-btn" onclick="_dzRemovePick()" ${(DZ.remove || {})[RM_PICK] === 'busy' ? 'disabled' : ''}>${(DZ.remove || {})[RM_PICK] === 'busy' ? 'Listing…' : 'Remove rules…'}</button>
        </div>
        <div class="dz-option">
          <div><div class="t">Export from tenant as a pack</div><div class="d">Read-only: lists the tenant's DLP rules on every channel, its custom engines and its custom dictionaries. Export any of them together or each on its own, with or without what they use, as a JSON pack, a Terraform workspace for the zscaler/zia provider, or both, and download each part (dictionaries, engines, rules) as its own file. Add a JSON pack to the library under Advanced settings → Add a pack, then deploy it here into this tenant or another one. Users, groups, locations and other scope that exists only in this tenant are left out and listed in the pack. Needs no write mode.</div></div>
          <button type="button" class="dz-btn" onclick="_dzExportPick()" ${DZ.exportBusy ? 'disabled' : ''}>${DZ.exportBusy ? 'Listing…' : 'Export as a pack…'}</button>
        </div>
        <div class="dz-option">
          <div><div class="t">DLP inventory (Excel)</div><div class="d">Read-only: a workbook of the tenant's DLP dictionaries (type, custom or predefined, clone of, patterns, phrases, confidence), engines (expression, dictionaries) and the rules of every DLP channel in scope (order, state, action, severity, engines, channel fields), each with who uses it. One sheet per kind, filterable. People named in rule scope are counted, not named. Needs no write mode.</div>
            <div class="dz-note" id="dzInvStatus" role="status" aria-live="polite">${_dzE((DZ.inventory || {}).note || '')}</div></div>
          <div style="display:flex;gap:var(--sp-2);flex-shrink:0;">${(DZ.inventory || {}).running
            ? `<button type="button" class="dz-btn" disabled>Reading…</button><button type="button" class="dz-btn" id="dzJobStop" onclick="_dzCancelJob()" ${_dzStopAsked() ? 'disabled' : ''}>${_dzStopAsked() ? 'Stopping…' : 'Stop'}</button>`
            : `<button type="button" class="dz-btn" onclick="_dzInventoryXlsx()">DLP inventory (Excel)</button>`}</div>
        </div>
      </div>
      ${_dzDeploymentsHtml()}`;
  }
  const sel = DZ.packs.filter(p => DZ.selected.has(p.id));
  const tot = k => sel.reduce((a, p) => a + (p[k] || 0), 0);
  document.getElementById('dzFoot').innerHTML = `
    <div class="dz-summary">${sel.length
      ? `<strong style="color:var(--text);">${_dzN(sel.length, 'pack')}</strong>${DZ.autoSelected && DZ.autoSelected.size && sel.every(p => DZ.autoSelected.has(p.id)) && sel.length === DZ.autoSelected.size ? ` <span class="d">(pre-selected for ${_dzE(DZ.autoIndustry || '')})</span>` : ''} · ${tot('dictionaries')} dictionaries · ${tot('engines')} engines · ${tot('policies')} policies<div class="d" style="margin-top:0.2rem;">Channels — ${_dzTargetsSummary(sel.map(p => p.id))}. Preflight reads the tenant and writes nothing.</div>`
      : 'Select at least one pack to continue.'}</div>
    <div class="dz-actions">
      <button type="button" class="dz-btn quiet" onclick="closeDlpPacksModal()">Cancel</button>
      <button type="button" class="dz-btn primary" ${sel.length ? '' : 'disabled'} onclick="_dzRunPreflight()">Run preflight <span aria-hidden="true">→</span></button>
    </div>`;
}

function _dzCardClick(e, id) {
  if (e.target.closest('.dz-detail, .dz-link, .dz-switch')) return;
  _dzTogglePack(id, !DZ.selected.has(id));
}
function _dzTogglePack(id, on) {
  if (on) DZ.selected.add(id); else DZ.selected.delete(id);
  _dzRenderSelect();
}
async function _dzToggleDetail(id) {
  if (DZ.open.has(id)) { DZ.open.delete(id); _dzRenderSelect(); return; }
  DZ.open.add(id);
  if (!DZ.details[id]) {
    _dzRenderSelect();
    try {
      const r = await fetch(`/api/dlp-packs/${encodeURIComponent(id)}`, { cache: 'no-store' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      DZ.details[id] = await r.json();
    } catch (e) { DZ.details[id] = { error: e.message }; }
  }
  _dzRenderSelect();
}
// Read-only journey check: same planner as preflight, nothing written,
// works without the write gate. Renders inline on the card.
// ── Rebuild the source-code pack from the tenant's dictionaries ─────
// Preview first (which Anchor/Signal pairs were found), then write.
function _dzFromTenantHtml() {
  const s = DZ.fromTenant;
  if (!s || s.busy) return '';
  if (s.error) return `<div class="dz-card sev-error" style="margin-top:0.6rem;"><div class="bar"></div><div><div class="t">Could not read the tenant's dictionaries</div><div class="d">${_dzE(s.error)}</div></div></div>`;
  const r = s.data;
  if (!r) return '';
  const langs = (r.languages || []).map(l => `<li><strong>${_dzE(l.language)}</strong>: anchor <code>${_dzE(l.anchor)}</code> (${l.anchor_patterns}) + signal <code>${_dzE(l.signal)}</code> (${l.signal_patterns} patterns)</li>`).join('');
  const extra = [...(r.unpaired || []).map(u => `unpaired: ${u}`), ...(r.ignored || []).map(i => `no Anchor/Signal in the name: ${i}`)];
  if (r.status === 'written') {
    return `<div class="dz-card sev-info" style="margin-top:0.6rem;"><div class="bar"></div><div><div class="t">Pack rebuilt from the tenant</div><div class="d">${_dzN((r.languages || []).length, 'language')}, ${_dzN(r.dictionaries || 0, 'dictionary', 'dictionaries')}, ${_dzN((r.engines || []).length, 'engine')}. Removed: ${_dzE((r.removed_engines || []).join(', ') || 'nothing')}. Rules rewired: ${_dzE((r.rules_rewired || []).join(', '))}. Terraform ${_dzE(r.terraform || '')}.</div>
      <ul class="dz-note">${langs}</ul></div></div>`;
  }
  return `<div class="dz-card sev-warning" style="margin-top:0.6rem;"><div class="bar"></div><div><div class="t">Preview: ${_dzN((r.languages || []).length, 'language pair')} found in ${_dzN(r.tenant_custom_dictionaries || 0, 'custom dictionary', 'custom dictionaries')}</div>
    <ul class="dz-note">${langs || '<li>No pairs.</li>'}</ul>
    ${extra.length ? `<div class="d">${_dzE(extra.join(' · '))}</div>` : ''}
    <div class="d">Engines will be <code>((Signal > ${_dzE(String(s.threshold))}) AND (Anchor > 0))</code>; the pack's current ${_dzN(r.replacing || 0, 'engine')} and their dictionaries are dropped. Nothing is written to the tenant.</div>
    <div class="dz-actions" style="margin-top:0.5rem;"><button type="button" class="dz-btn primary" onclick="_dzFromTenant('${_dzE(s.id)}', true)">Rebuild the pack</button><button type="button" class="dz-btn" onclick="DZ.fromTenant=null;_dzRenderSelect()">Cancel</button></div></div></div>`;
}
async function _dzFromTenant(id, confirm) {
  let filter = (DZ.fromTenant && DZ.fromTenant.filter) || '';
  let threshold = (DZ.fromTenant && DZ.fromTenant.threshold) || 4;
  if (!confirm) {
    const f = window.prompt('Which dictionaries? Enter a name prefix or pattern (for example SRC- or v4), or leave empty for every custom dictionary whose name contains Anchor or Signal.', filter);
    if (f === null) return;
    filter = f.trim();
    const t = window.prompt('Signal matches an engine needs (> N). HTML uses N-1.', String(threshold));
    if (t === null) return;
    threshold = Math.max(0, parseInt(t, 10) || 0);
  }
  DZ.fromTenant = { id, busy: true, filter, threshold };
  _dzRenderSelect();
  try {
    const r = await fetch(`/api/dlp-packs/${encodeURIComponent(id)}/from-tenant`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name_filter: filter, threshold, html_threshold: Math.max(0, threshold - 1), confirm: !!confirm, ..._dzCreds() }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((data.detail && (data.detail.cause || data.detail)) || `HTTP ${r.status}`);
    if (data.status === 'error') throw new Error(data.error || 'no pairs found');
    const pack = (DZ.packs || []).find(p => p.id === id) || {};
    data.replacing = pack.engines || 0;
    DZ.fromTenant = { id, data, filter, threshold };
    announce(data.status === 'written' ? `Pack ${id} rebuilt from ${data.languages.length} tenant language pairs.` : `${data.languages.length} language pairs found; review and confirm.`);
    if (data.status === 'written') {
      try { const pr = await fetch('/api/dlp-packs', { cache: 'no-store' }); if (pr.ok) DZ.packs = (await pr.json()).packs || DZ.packs; } catch (e) { /* keep the old card counts */ }
    }
  } catch (e) {
    DZ.fromTenant = { id, error: e.message, filter, threshold };
  }
  _dzRenderSelect();
}

async function _dzJourney(id) {
  DZ.journey[id] = { busy: true };
  _dzRenderSelect();
  try {
    const r = await fetch('/api/dlp-packs/journey', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pack_ids: [id], channel_targets: _dzTargets([id]), ..._dzCreds() }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((data.detail && (data.detail.cause || data.detail)) || `HTTP ${r.status}`);
    DZ.journey[id] = { data, at: new Date() };
    const b = (data.baselines || [])[0] || {};
    announce(`Policy pack ${id}: stage ${b.stage || 0} of 5, ${b.stage_name || 'not started'}.`);
  } catch (e) {
    DZ.journey[id] = { error: e.message };
  }
  _dzRenderSelect();
}
// Terraform export: one workspace per pack for the official zscaler/zia
// provider. With credentials the server runs a preflight first and emits
// import blocks for existing objects (gap mode), so `terraform plan` is the
// gap between the tenant and the pack.
// It runs as a background job the page follows (gap mode reads the whole
// tenant first, which is a minute of API calls): the hand-off page shows
// each read as it happens, then the zip is fetched from the finished job.
async function _dzTerraform(ids, mode) {
  DZ.tfBusy = ids.length === 1 ? ids[0] : '*';
  if (DZ.step === 1) _dzRenderSelect();
  TF.last = null;
  try {
    _dzNeedAssessor();
    // Static mode sends no credentials at all, so the server never reads the tenant.
    const creds = mode === 'static' ? { client_id: '', client_secret: '', vanity_domain: '', username: '', password: '', api_key: '', cloud: (_dzCreds() || {}).cloud || 'production', assessor: (_dzCreds() || {}).assessor || '' } : _dzCreds();
    const snap = await _dzRunJob('/api/dlp-packs/terraform/start', { pack_ids: ids, use_rank_0: DZ.options.use_rank_0, channel_targets: _dzTargets(ids), mode: mode || '', ...creds });
    if (snap.status === 'failed' || !snap.result) throw new Error(snap.error || 'The hand-off ended without a result.');
    if (snap.result.status === 'stopped' || !snap.download) throw new Error(snap.result.stopped || 'The hand-off was stopped before the workspace was built.');
    const r = await fetch(snap.download, { cache: 'no-store' });
    if (!r.ok) throw new Error(`The workspace could not be fetched (HTTP ${r.status}).`);
    const got = r.headers.get('X-DLP-Check-Mode') || snap.result.mode || 'static';
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = snap.filename || snap.result.filename || 'zscaler-made-easy-terraform.zip';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    TF.last = Object.assign({}, snap.result, { logs: snap.logs, elapsed_seconds: snap.elapsed_seconds });
    announce(`Terraform workspace downloaded (${got === 'gap' ? 'gap mode: existing objects will be imported' : 'static: no tenant credentials given'}).`);
  } catch (e) {
    TF.last = { status: 'failed', error: e.message, logs: (DZ.job || {}).logs || [] };
    alert(`Terraform export failed: ${e.message}`);
  } finally {
    DZ.tfBusy = null;
    if (DZ.step === 1) _dzRenderSelect();
  }
}

const DZ_POSITION = {
  missing:    { label: 'Missing',     cls: 'info', help: 'Not in the tenant yet. Deploying the policy pack creates it.' },
  deployed:   { label: 'Deployed',    cls: 'ok',   help: 'Present as the policy pack defines it; the rule is still disabled.' },
  monitoring: { label: 'Monitoring',  cls: 'ok',   help: 'Enabled with a non-enforcing action: incidents are logged, users are not blocked.' },
  enforcing:  { label: 'Enforcing',   cls: 'ok',   help: 'Enabled with an enforcing action (BLOCK, DECRYPT, CAUTION…).' },
  customized: { label: 'Customized',  cls: 'warn', help: 'Present but changed by the customer. Kept exactly as it is; the change is not reverted.' },
  relaxed:    { label: 'Relaxed',     cls: 'warn', help: 'The policy pack ships this rule enabled but the tenant has disabled it.' },
  blocked:    { label: 'Blocked',     cls: 'fail', help: 'Cannot be created: a prerequisite is missing or there is a conflict.' },
};
const DZ_JOURNEY_STATE = {
  not_started: { label: 'Not started', cls: 'info' },
  in_progress: { label: 'In progress', cls: 'warn' },
  governed:    { label: 'Governed',    cls: 'ok' },
  blocked:     { label: 'Blocked',     cls: 'fail' },
};
// Stage ladder + counts + next steps for one policy pack row (shared by the
// pack card and the assessment card).
function _dzJourneyRowHtml(b, opts = {}) {
  const st = DZ_JOURNEY_STATE[b.state] || DZ_JOURNEY_STATE.blocked;
  const ladder = (b.stages || []).map(sg => {
    const cur = !sg.done && (b.stages.slice(0, sg.n - 1).every(x => x.done));
    return `<li class="dz-stage ${sg.done ? 'done' : (cur ? 'cur' : '')}" title="${_dzE(sg.what)}${sg.required ? ` (${sg.met} of ${sg.required} objects ready)` : ' (nothing in this policy pack needs it)'}">
      <span class="n">${sg.done ? '✓' : sg.n}</span><span class="nm">${_dzE(sg.name)}</span>${sg.required ? `<span class="ct">${sg.met}/${sg.required}</span>` : ''}</li>`;
  }).join('');
  const counts = ['missing', 'deployed', 'monitoring', 'enforcing', 'customized', 'relaxed', 'blocked']
    .filter(k => b[k]).map(k => `<span title="${_dzE(DZ_POSITION[k].help)}"><b>${b[k]}</b> ${DZ_POSITION[k].label.toLowerCase()}</span>`).join(' · ');
  const objs = (b.objects || []).filter(o => o.position !== 'deployed' && o.position !== 'monitoring' && o.position !== 'enforcing').slice(0, opts.max || 8);
  return `
    <div class="dz-journey-top"><span class="dz-status ${b.state === 'governed' ? 'ready' : (b.state === 'blocked' ? 'blocked' : 'warnings')}">${st.label}</span>
      <span class="lead">Stage ${b.stage || 0} of 5${b.stage ? `: ${_dzE(b.stage_name)}` : ''}</span>
      <span class="score" title="Share of the objects each stage needs that are already where they should be, averaged over the stages.">${b.score ?? 0}%</span>
      ${opts.label ? `<span class="when">${_dzE(opts.label)}</span>` : ''}</div>
    <ol class="dz-stages">${ladder}</ol>
    <div class="counts">${counts || 'No objects.'}</div>
    ${(b.next_steps || []).length ? `<div class="dz-next-h">Next steps</div><ol class="dz-next">${b.next_steps.map(n => `<li>${_dzE(n)}</li>`).join('')}</ol>` : (b.state === 'governed' ? `<div class="d">Every object of this policy pack is deployed, enabled and enforcing. Keep reviewing incidents; update the pack when the customer tunes something.</div>` : '')}
    ${_dzSbdHtml(b.secure_by_design)}
    ${objs.length ? `<details class="dz-fold"><summary>Objects not yet in place (${objs.length}${(b.objects || []).length > objs.length ? ' shown' : ''})</summary><ul class="dz-objs">${objs.map(o => `<li><span class="dz-chip kind-${_dzE(o.kind)}">${DZ_KIND[o.kind] || o.kind}</span> <span class="nm">${_dzE(o.name)}</span> <span class="st ${_dzE((DZ_POSITION[o.position] || {}).cls || '')}" title="${_dzE((DZ_POSITION[o.position] || {}).help || '')}">${_dzE((DZ_POSITION[o.position] || {}).label || o.position)}${o.drift && o.drift.length ? ` · ${_dzE(o.drift.join(', '))}` : ''}${o.action && o.position !== 'missing' && String(o.action).length <= 40 ? ` · ${_dzE(o.action)}` : ''}</span></li>`).join('')}</ul></details>` : ''}`;
}
// CISA Secure by Design, measured on the deployed pack: what is not in
// place, what was changed without the pack knowing, what was weakened.
function _dzSbdHtml(s) {
  if (!s) return '';
  const sev = { high: 'sev-high', medium: 'sev-warning', info: 'sev-info', none: 'sev-info' };
  const items = (s.findings || []).map(f => `<li class="dz-sbd-f ${sev[f.severity] || 'sev-info'}"><div class="t"><span class="dz-chip kind-muted">${_dzE(f.principle)}</span> ${_dzE(f.title)}</div><div class="d">${_dzE(f.detail)}</div><div class="d"><strong>What to do:</strong> ${_dzE(f.next)}</div>${(f.objects || []).length ? `<div class="d dz-sbd-objs">${f.objects.map(o => _dzE(o.name)).join(', ')}${f.count > f.objects.length ? ` and ${f.count - f.objects.length} more` : ''}</div>` : ''}</li>`).join('');
  return `<details class="dz-fold dz-sbd" ${s.ok ? '' : 'open'}><summary>Secure by Design (this pack's objects in the tenant): ${s.ok ? 'no deviation from the pack' : `${(s.findings || []).length} finding(s), highest ${_dzE(s.level)}`}</summary>
    <div class="d">CISA's Secure by Design principles applied to this pack's own objects as they are in the tenant — not a compliance score for the tenant: the whole design deployed (ownership of outcomes), every change recorded in the pack (transparency), nothing weakened against it (secure defaults).</div>
    ${items ? `<ul class="dz-sbd-list">${items}</ul>` : '<div class="d">Every object is where the pack says it should be, and nothing has been changed or weakened outside the pack.</div>'}</details>`;
}

function _dzJourneyHtml(id) {
  const s = DZ.journey[id];
  if (!s || s.busy) return s && s.busy ? `<div class="dz-journey" onclick="event.stopPropagation()"><span class="dz-status busy">Measuring</span> Reading the tenant…</div>` : '';
  if (s.error) return `<div class="dz-journey is-error" onclick="event.stopPropagation()"><strong>Could not measure the journey.</strong> ${_dzE(s.error)}</div>`;
  const b = (s.data.baselines || [])[0];
  if (!b) return '';
  const st = DZ_JOURNEY_STATE[b.state] || DZ_JOURNEY_STATE.blocked;
  return `<div class="dz-journey ${st.cls}" onclick="event.stopPropagation()">${_dzJourneyRowHtml(b, { label: s.data.tenant_label || '' })}
    ${b.missing ? `<div class="d">Select the pack and run preflight to create the ${_dzN(b.missing, 'missing object')}; everything that exists stays as it is.</div>` : ''}
  </div>`;
}

function _dzDetailHtml(id) {
  const d = DZ.details[id];
  if (!d) return `<div class="dz-detail">Loading…</div>`;
  if (d.error) return `<div class="dz-detail" style="color:var(--fail);">${_dzE(d.error)}</div>`;
  const li = (items, f) => items.length ? items.map(f).join('') : '<li>none</li>';
  return `<div class="dz-detail" onclick="event.stopPropagation()">
    <div><strong>Dictionaries</strong><ul>${li(d.dictionaries.items, x => `<li><span>${_dzE(x.name)}</span><span>${x.type}${x.proximity ? ` · prox ${x.proximity}` : ''}</span></li>`)}</ul></div>
    <div><strong>Engines</strong><ul>${li(d.engines.items, x => `<li><span>${_dzE(x.name)}</span></li>`)}</ul></div>
    <div><strong>Policies</strong><ul>${li(d.policies.items, x => `<li><span>${_dzE(x.name)}</span><span>${x.channel && x.channel !== 'web' ? _dzE(_dzChan(x.channel)) + ' · ' : ''}${_dzE(x.action)}</span></li>`)}</ul></div>
  </div>`;
}

// ── Step 2: preflight ─────────────────────────────────────────────
async function _dzRunPreflight() {
  DZ.step = 2; DZ.report = null; DZ.error = ''; DZ.busy = true; DZ.consent = false; DZ.requestNote = '';
  _dzRender();
  try {
    const r = await fetch('/api/dlp-packs/preflight', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pack_ids: [...DZ.selected], ...DZ.options, channel_targets: _dzTargets([...DZ.selected]), scopes: _dzRankScopes(), ..._dzCreds() }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
    DZ.report = data;
    const c = _dzCounts(data);
    announce(`Preflight ${data.status}: ${c.create} to create, ${c.modify + c.restore} to change, ${c.blocked} skipped or in conflict, ${(data.warnings || []).length} warnings.`);
  } catch (e) {
    DZ.error = e.message;
  } finally {
    DZ.busy = false; _dzRender();
  }
}

function _dzRow(i, statusKey, extra) {
  const st = DZ_STATUS[statusKey] || { label: statusKey, cls: 'st-reuse', icon: '•' };
  const reason = extra || i.reason || i.error || '';
  // The admin rank a new rule takes and why (rank_inherit), and what the read-back found.
  const rk = i.rank_plan;
  const rankLine = rk ? `Admin rank ${rk.rank}${rk.order ? `, order ${rk.order}` : ''}: ${rk.why || ''}` : '';
  const stored = i.stored ? `Read back: ${i.stored}.` : '';
  return `<div class="dz-row ${st.cls}">
    <span class="ic" aria-hidden="true">${st.icon}</span>
    <div><div class="nm">${_dzE(i.name)}</div>${reason ? `<div class="rs">${_dzE(reason)}</div>` : ''}${rankLine ? `<div class="rs dz-rank">${_dzE(rankLine)}</div>` : ''}${rk && rk.warning ? `<div class="rs dz-rank-warn">${_dzE(rk.warning)}</div>` : ''}${stored ? `<div class="rs dz-rank-warn">${_dzE(stored)}</div>` : ''}</div>
    <div class="tags"><span class="dz-chip kind-${i.kind}" title="${_dzE(DZ_KIND_HELP[i.kind] || '')}">${DZ_KIND[i.kind] || i.kind}</span>${i.detail && i.detail.channel ? `<span class="dz-chip kind-channel" title="${_dzE(DZ_CHANNEL_HELP[i.detail.channel] || '')}">${_dzE(_dzChan(i.detail.channel))}</span>` : ''}${i.extension ? `<span class="dz-chip kind-baseline" title="Added by your channel selection: a monitor-only rule carrying the pack's engines on a channel the pack ships no rule for.">channel add-on</span>` : ''}${i.detail && i.detail.target_action ? `<span class="dz-chip" title="Ships monitor-only (${_dzE(i.detail.action)}) and DISABLED like every pack rule; it was designed to ${_dzE(i.detail.target_action)}. The journey card names it as the hardening step once incidents are reviewed.">target ${_dzE(i.detail.target_action)}</span>` : ''}<span class="dz-chip" title="${_dzE(st.help || '')}">${st.label}</span>${(i.packs || []).slice(0, 2).map(p => `<span class="dz-chip" title="Defined by pack ${_dzE(p)}">${_dzE(p)}</span>`).join('')}</div>
  </div>`;
}

// Tenant prerequisites per channel (SaaS tenants onboarded, feature APIs
// answering, notification templates, labels...). Comes from the planner's
// `dependencies` list; each row names the rules that need it.
const DZ_DEP = {
  ok:      { cls: 'st-ok',      icon: '✓', label: 'Present' },
  missing: { cls: 'st-blocked', icon: '✕', label: 'Missing' },
  error:   { cls: 'st-fail',    icon: '!', label: 'Unavailable' },
  info:    { cls: 'st-reuse',   icon: 'i', label: 'Note' },
};
// Preflight check: will this run succeed at ZIA's rate limits, from ZIA's recent answers.
function _dzRateCheck(f, blocked) {
  if (!f || blocked) return '';
  const sev = { ok: 'ok', warn: 'warning', fail: 'error' }[f.severity] || 'info';
  const local = f.run_after ? ` (${new Date(f.run_after * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} your time)` : '';
  return `<div class="dz-card sev-${sev}" style="margin-top:0.9rem;" role="status"><div class="bar"></div><div>
    <div class="t">Rate-limit check: ${_dzE(f.title || '')}</div><div class="d">${_dzE(f.verdict)}${_dzE(local)}</div>
    ${(f.plan || []).length ? `<div class="d" style="margin-top:0.35rem;"><strong>API plan</strong><br>${f.plan.map(l => `• ${_dzE(l)}`).join('<br>')}</div>` : ''}
    ${f.success ? `<div class="d" style="margin-top:0.35rem;"><strong>Success</strong> — ${_dzE(f.success.text)}</div>` : ''}
    ${f.detail ? `<div class="d" style="margin-top:0.3rem;color:var(--dim);">${_dzE(f.detail)}</div>` : ''}</div></div>`;
}

function _dzDepsHtml(deps) {
  if (!deps || !deps.length) return '';
  const missing = deps.filter(d => d.status === 'missing' || d.status === 'error').length;
  const rows = deps.map(d => {
    const s = DZ_DEP[d.status] || DZ_DEP.info;
    return `<div class="dz-row ${s.cls}">
      <span class="ic" aria-hidden="true">${s.icon}</span>
      <div><div class="nm">${_dzE(d.requirement)}</div><div class="rs">${_dzE(d.detail || '')}${d.rules && d.rules.length ? ` — needed by ${_dzE(d.rules.slice(0, 4).join(', '))}${d.rules.length > 4 ? ` +${d.rules.length - 4} more` : ''}` : ''}</div></div>
      <div class="tags"><span class="dz-chip kind-channel">${_dzE(_dzChan(d.channel))}</span><span class="dz-chip">${s.label}</span></div>
    </div>`;
  }).join('');
  return `<details class="dz-fold" open><summary><div class="dz-h">Tenant prerequisites<span class="count">${deps.length}</span>${missing ? `<span class="dz-chip kind-missing">${missing} missing</span>` : ''}</div></summary>
    <p class="dz-note">What each channel needs from the tenant before its rules can be created. Missing prerequisites skip only the rules that need them.</p>
    <div class="dz-rows">${rows}</div></details>`;
}
function _dzSection(title, items, { open = true, fn } = {}) {
  if (!items.length) return '';
  const rows = `<div class="dz-rows">${items.map(fn || (i => _dzRow(i, i.status))).join('')}</div>`;
  return `<details class="dz-fold" ${open ? 'open' : ''}><summary><div class="dz-h">${title}<span class="count">${items.length}</span></div></summary>${rows}</details>`;
}

// One count vocabulary for the whole Studio (hero, tiles, gates, the
// announcement): create / modify / restore are the writes, reuse_differs is
// kept as-is, conflicts and skips are separate, reuse and noop are "already
// in place". Nothing else counts items.
function _dzCounts(R) {
  const items = (R && R.items) || [];
  const n = s => items.filter(i => i.status === s).length;
  const c = { create: n('create'), modify: n('modify'), restore: n('restore'), differs: n('reuse_differs'),
              conflict: n('conflict'), dependency: n('blocked_dependency'), empty: n('skip_empty'), reuse: n('reuse'), noop: n('noop') };
  c.writes = c.create + c.modify + c.restore;
  c.blocked = c.conflict + c.dependency + c.empty;
  c.inplace = c.reuse + c.noop;
  return c;
}
function _dzRenderReview() {
  const body = document.getElementById('dzBody');
  const foot = document.getElementById('dzFoot');
  if (DZ.busy) {
    body.innerHTML = `<div class="dz-hero"><span class="dz-status busy">Checking</span><div><div class="lead">Reading your tenant…</div><div class="sub">Dictionaries, engines and DLP rules are being cross-referenced with the selected packs.</div></div></div><div class="dz-progress"><div class="bar"></div></div>`;
    foot.innerHTML = `<div class="dz-summary">Nothing is written during preflight.</div><div class="dz-actions"><button class="dz-btn quiet" disabled>Back</button><button class="dz-btn primary" disabled>Review &amp; approve →</button></div>`;
    return;
  }
  if (DZ.error) {
    body.innerHTML = `<div class="dz-card sev-error"><div class="bar"></div><div><div class="t">Preflight couldn't run</div><div class="d">${_dzE(DZ.error)}</div><div class="d" style="margin-top:0.4rem;">Check the tenant credentials at the top of the page (cloud, vanity domain, client ID, client secret) and try again.</div></div></div>`;
    foot.innerHTML = `<div class="dz-summary"></div><div class="dz-actions"><button class="dz-btn" onclick="DZ.step=1;_dzRender()">← Back</button><button class="dz-btn primary" onclick="_dzRunPreflight()">Try again</button></div>`;
    return;
  }
  const R = DZ.report;
  const items = R.items || [];
  const by = s => items.filter(i => i.status === s);
  const restores = by('restore');
  const creates = [...by('create'), ...by('modify'), ...restores];
  const differs = by('reuse_differs');
  const conflicts = by('conflict');
  const skipped = [...by('blocked_dependency'), ...by('skip_empty')];
  const reused = [...by('reuse'), ...by('noop')];
  const c = _dzCounts(R);
  const lead = { ready: 'Ready to deploy', warnings: 'Ready, with things to review', blocked: 'Deployment is blocked' }[R.status];
  // The same numbers as the tiles and the gates, in one line.
  const sub = `${_dzN(c.create, 'object')} to create${c.modify ? ` · ${c.modify} to modify` : ''}${c.restore ? ` · ${c.restore} to overwrite (converge)` : ''} · ${c.differs} kept as-is${c.conflict ? ` · ${_dzN(c.conflict, 'conflict')}` : ''} · ${c.dependency + c.empty} skipped · ${c.inplace} already in place`;
  const t = R.tenant || {};
  body.innerHTML = `
    <div class="dz-hero">
      <span class="dz-status ${R.status}">${lead}</span>
      <div><div class="lead">${_dzE(R.tenant_label || 'tenant')}</div><div class="sub">${sub}</div></div>
    </div>
    <div class="dz-kv">
      <div><div class="k">Will create</div><div class="v">${c.create}</div></div>
      <div><div class="k">${c.restore ? 'Will overwrite / modify' : 'Will modify'}</div><div class="v">${c.modify + c.restore}</div></div>
      <div><div class="k">Kept as-is</div><div class="v">${c.differs}</div></div>
      <div><div class="k">${c.conflict ? 'Skipped / conflicts' : 'Skipped'}</div><div class="v">${c.blocked}</div></div>
      <div><div class="k">Tenant rules</div><div class="v">${t.rules ?? '–'}<span style="font-size:0.75rem;color:var(--dim);font-weight:500;"> / ${t.rule_cap || 127}</span></div></div>
    </div>
    ${R.report_id ? `<div class="dz-pick-tools" style="margin-top:0.7rem;" role="group" aria-label="Download the plan for change approval">
      <span class="dz-note" style="margin:0;">For change approval, with a sign-off block:</span>
      <button type="button" class="dz-btn" onclick="_dzPlanDownload('pdf')">Plan (PDF)</button>
      <button type="button" class="dz-btn" onclick="_dzPlanDownload('xlsx')">Plan (Excel)</button></div>` : ''}
    ${(R.blockers || []).map(b => `<div class="dz-card sev-error" style="margin-top:0.9rem;"><div class="bar"></div><div><div class="t">Blocked</div><div class="d">${_dzE(b)}</div></div></div>`).join('')}
    ${R.rehearsal ? `<div class="dz-card sev-info" id="dzRehearsal" role="note" style="margin-top:0.9rem;"><div class="bar"></div><div><div class="t">${_dzE(R.rehearsal.note)}</div><div class="d">${_dzE(R.rehearsal.apply)}</div></div></div>` : ''}
    ${_dzRateCheck(R.rate_forecast, R.status === 'blocked')}
    <details class="dz-fold dz-howto"><summary><div class="dz-h">How to read this plan</div></summary>
      <ul class="dz-note">
        <li><strong>Nothing has been written.</strong> This is a dry run against the live tenant.</li>
        <li><strong>Impact cards</strong> say what changes for the tenant as a whole: greenfield or brownfield, rules inserted at the top of the policy, enforcing actions, activation.</li>
        <li><strong>Existing objects are not overwritten.</strong> A rule the customer enabled or hardened, or a dictionary they tuned, is kept exactly as it is and shown as <em>Kept as-is</em>. What is missing gets created (<em>Will create</em>). The one change to an existing object is a confidence tweak on a dictionary the pack tunes, listed as <em>Will modify</em> (turn off <em>Apply confidence tweaks</em> on the Select step to avoid it); converge mode, when asked for, overwrites and is listed as <em>Will overwrite</em>.</li>
        <li><strong>Skipped vs conflict.</strong> <em>Skipped: needs a prerequisite</em> and <em>Skipped: empty</em> are left out and everything else still deploys; a <em>Conflict</em> (two packs, or a predefined Zscaler name) must be resolved by deselecting a pack or renaming.</li>
        <li><strong>Tenant prerequisites</strong> are things the tenant must already have (a predefined dictionary, an onboarded SaaS tenant, a licensed feature). Missing ones skip only the rules that need them.</li>
        <li><strong>The lists</strong> group the objects by what will happen to them. Hover any status chip for what it means. The dependency diagram (dictionaries feed engines feed rules) is on the <em>How a deployment works</em> page.</li>
        <li>Every rule ships <strong>DISABLED</strong>, so deploying never affects users. Enable rules in the portal after tuning.</li>
        <li><strong>Two ways to close the gap.</strong> <em>Review &amp; approve</em> creates the missing objects from here (write mode needed). <em>Hand off as Terraform</em> gives a platform team the same objects as a Terraform workspace: in gap mode its first <code>terraform plan</code> creates what this list creates and imports what already exists (an object the customer customized then shows as an update in place; the hand-off notes say how to keep their version).</li>
      </ul></details>
    ${(R.impacts || []).length ? `<div class="dz-h">Impact on this tenant</div>` : ''}
    ${(R.impacts || []).map(i => `<div class="dz-card sev-${_dzE(i.severity)}"><div class="bar"></div><div><div class="t">${_dzE(i.title)}</div><div class="d">${_dzE(i.detail)}</div></div></div>`).join('')}
    ${_dzDepsHtml(R.dependencies)}
    ${_dzSection('Converge mode — will be overwritten with the policy pack', restores)}
    ${_dzSection('Changes that will be written', creates.filter(i => i.status !== 'restore'))}
    ${_dzSection('Already exist, customized by the customer — kept as-is', differs)}
    ${_dzSection('Conflicts — resolve before deploying (deselect a pack or rename)', conflicts)}
    ${_dzSection('Skipped — a prerequisite is missing, or the dictionary is empty', skipped)}
    ${_dzSection('Already in place — nothing to do', reused, { open: false })}`;
  _dzFlowSyncTab(items, null);   // the standalone flow page, if open, follows the plan
  foot.innerHTML = `
    ${_dzGatesHtml(R, { step: 2 })}
    <div class="dz-summary">${R.status === 'blocked' ? 'Resolve the blockers above, then run preflight again.' : 'Nothing has been written yet.'}</div>
    <div class="dz-actions">
      <button type="button" class="dz-btn" onclick="DZ.step=1;_dzRender()">← Back</button>
      <button type="button" class="dz-btn" onclick="_dzRunPreflight()">Re-run</button>
      <button type="button" class="dz-btn" title="Close this gap with Terraform instead: opens the hand-off page for the selected packs (what you get, how to run it, download in gap mode so the first terraform plan creates only what is missing here and imports the rest)." onclick="openToolTab('terraform', [...DZ.selected].join(','))">Hand off as Terraform</button>
      <button type="button" class="dz-btn" id="dzRequestApproval" ${R.status === 'blocked' || !R.plan_hash || !c.writes ? 'disabled' : ''} title="File this plan in the change queue for another writer to approve. Nothing is written now; an approved request is applied from the change queue after the plan is checked against the tenant again." onclick="_dzRequestApproval('deploy')">Request approval</button>
      <button type="button" class="dz-btn primary" ${R.status === 'blocked' ? 'disabled' : ''} onclick="DZ.step=3;DZ.consent=false;_dzRender()">Review &amp; approve <span aria-hidden="true">→</span></button>
    </div>${_dzRequestedHtml(R.plan_hash)}`;
}

// ── Request approval: file the plan in the team change queue ─────
// The server files the plan its own preflight (or removal preview) made
// for this plan_hash, names the requester itself, and writes nothing to
// the tenant. Another writer approves it on the Change queue page.
function _dzRequestedHtml(hash) {
  const q = DZ.requested;
  if (DZ.requestNote) return `<div class="dz-summary" role="status">${_dzE(DZ.requestNote)}</div>`;
  if (!q || !hash || q.hash !== hash) return '';
  return `<div class="dz-summary" role="status">Approval requested: <code>${_dzE(q.id)}</code> is pending in the <a href="/report/queue" target="_blank" rel="noopener">change queue</a>.</div>`;
}
async function _dzRequestApproval(kind) {
  const removal = kind === 'removal';
  const R = removal ? (DZ.removal || {}).plan : DZ.report;
  if (!R || !R.plan_hash) return;
  const dlg = _dzDlg();
  const what = removal ? `the removal of ${_dzN((R.items || []).filter(i => i.status === 'remove').length, 'object')}` : `${_dzN(_dzCounts(R).writes, 'change')}`;
  const q = { title: 'Request approval for this plan?',
    body: `The plan (${what} to ${R.tenant_label || 'the tenant'}, plan ${String(R.plan_hash).slice(0, 12)}) is saved in the change queue on this server, with you as the requester. Nothing is written now. Another writer reviews it there and approves or rejects it; an approved request is applied from the change queue after the plan is checked against the tenant again.`,
    okLabel: 'Request approval' };
  let ok = false;
  if (dlg) ok = await dlg.ask(q);
  else { try { ok = window.confirm(`${q.title}\n\n${q.body}`); } catch (e) { ok = false; } }
  if (!ok) return;
  DZ.requestNote = '';
  try {
    const body = removal
      ? { ..._dzRemovalScope(), plan_hash: R.plan_hash, ..._dzCreds() }
      : { pack_ids: [...DZ.selected], ...DZ.options, channel_targets: _dzTargets([...DZ.selected]), scopes: _dzRankScopes(), plan_hash: R.plan_hash, ..._dzCreds() };
    const r = await fetch(removal ? '/api/change-queue/removal' : '/api/change-queue/deploy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((data.detail && (data.detail.cause || data.detail)) || `HTTP ${r.status}`);
    DZ.requested = { id: data.request.id, hash: R.plan_hash };
    announce(`Approval requested: ${data.request.id} is pending in the change queue.`);
    if (dlg) await dlg.notice({ title: 'Approval requested', tone: 'ok',
      body: `Request ${data.request.id} is pending in the change queue. Open Change queue (toolbar) to follow it, add a comment or withdraw it; another writer approves it there.` });
  } catch (e) {
    DZ.requestNote = `Could not request approval: ${e.message}`;
    announce(DZ.requestNote);
  }
  if (removal) _dzRemovalRender(); else _dzRender();
}


// ── Why can't I deploy? Every gate in one list ───────────────────
// A person who cannot find the Deploy button enabled sees which gate is
// closed and what opens it, instead of a greyed-out button.
function _dzGatesHtml(R, { step } = {}) {
  const w = DZ.write || {};
  const c = _dzCounts(R);
  const gates = [];
  const writesText = `${_dzN(c.create, 'object')} to create${c.modify ? `, ${c.modify} to modify` : ''}${c.restore ? `, ${c.restore} to overwrite` : ''}`;
  if (!R) gates.push({ ok: false, text: 'Run preflight first: it reads the tenant and builds the plan.' });
  else if (R.status === 'blocked') gates.push({ ok: false, text: `The plan is blocked: ${(R.blockers || ['see the reason above']).join(' ')}` });
  else gates.push({ ok: true, text: `The plan can be deployed (${writesText}${R.status === 'warnings' ? '; read the warnings' : ''}).` });
  if (R && R.status !== 'blocked') gates.push(c.writes ? { ok: true, text: `There is something to write (${writesText}).` }
    : { ok: false, text: c.blocked && !c.inplace ? `Nothing to write: every object is skipped or in conflict (${c.conflict} conflict, ${c.dependency + c.empty} skipped); read the plan's sections.`
      : c.blocked ? `Nothing to write: ${c.inplace + c.differs} object(s) already exist and ${c.blocked} are skipped or in conflict.`
      : 'Nothing to write: every object of this pack already exists in the tenant (the journey card shows how far it is).' });
  if (c.conflict) gates.push({ ok: false, warn: true, text: `${_dzN(c.conflict, 'conflict')}: those objects and what depends on them are left out until you deselect a pack or rename.` });
  // A packed channel left unticked is said here, before approval, not only in the log afterwards.
  for (const u of _dzUntickedChannels([...DZ.selected])) {
    gates.push({ ok: false, warn: true, text: `${u.name}: ${u.labels.join(', ')} unticked — the ${_dzN(u.rules, 'rule')} this pack ships there will NOT be deployed. Go back to Select and tick the channel${u.labels.length === 1 ? '' : 's'} to deploy them.` });
  }
  if (w.enabled) gates.push({ ok: false, warn: true, text: 'Write mode is on for this server (every browser using it) until the server restarts.' });
  else gates.push({ ok: false, text: w.can_toggle ? 'Write mode is off: click Enable write mode and type the confirmation phrase.' : `Write mode is off and cannot be enabled from here${w.reason ? ': ' + w.reason : (w.how_to_enable ? ': ' + w.how_to_enable + '.' : '.')}` });
  if (step === 3) gates.push(DZ.consent ? { ok: true, text: 'You have ticked the approval box.' } : { ok: false, text: 'Tick the approval box above.' });
  else gates.push({ ok: true, text: 'Next: Review & approve, tick the approval box, then Deploy to tenant.' });
  return `<ul class="dz-gates" aria-label="What a deployment needs">${gates.map(g => `<li class="${g.ok ? 'ok' : (g.warn ? 'warn' : 'closed')}"><span class="ic" aria-hidden="true">${g.ok ? '✓' : (g.warn ? '!' : '✕')}</span><span class="sr-only">${g.ok ? 'Open: ' : (g.warn ? 'Warning: ' : 'Closed: ')}</span>${_dzE(g.text)}</li>`).join('')}</ul>`;
}
// Packed channels left unticked for the given packs: [{ name, labels, rules }].
function _dzUntickedChannels(ids) {
  const out = [];
  for (const id of ids) {
    const p = DZ.packs.find(x => x.id === id);
    if (!p) continue;
    const on = new Set(_dzChannelsFor(id));
    const off = DZ_DLP.filter(c => (p.channels || {})[c] && !on.has(c));
    if (off.length) out.push({ name: p.name || p.id, labels: off.map(c => DZ_DLP_LABEL[c]), rules: off.reduce((n, c) => n + (p.channels[c] || 0), 0) });
  }
  return out;
}

// ── Background jobs: a deploy or removal the browser follows live ──
// The tenant work runs on the server as a job (POST .../start → job id);
// the page polls GET /api/dlp-packs/jobs/{id} for new log lines and the
// elapsed time, and gets the result when the job finishes. Stop asks the
// server to send nothing more after the write in flight.
async function _dzStartJob(url, body, startToken) {
  const headers = { 'Content-Type': 'application/json' };
  if (startToken) headers['X-Start-Token'] = startToken;   // lets a Stop pressed before the id arrives reach the job
  const r = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((data.detail && (data.detail.cause || data.detail)) || `HTTP ${r.status}`);
  if (!data.job_id) throw new Error('The server did not start the run (no job id).');
  return data.job_id;
}
async function _dzFollowJob(jobId, onUpdate) {
  let next = 0, misses = 0;
  const logs = [];
  for (;;) {
    await new Promise(res => setTimeout(res, 1500));
    let snap;
    try {
      const r = await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(jobId)}?since=${next}`, { cache: 'no-store' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      snap = await r.json();
      misses = 0;
    } catch (e) {
      if (++misses >= 20) throw new Error(`Lost contact with the app while the run continued (${e.message}). The run keeps going on the server; check the tenant with "Where is this tenant?" on the pack card.`);
      continue;
    }
    logs.push(...(snap.logs || []));
    next = snap.next;
    onUpdate(Object.assign({}, snap, { logs }));
    if (snap.status !== 'running') return Object.assign({}, snap, { logs });
  }
}
function _dzMMSS(seconds) {
  const s = Math.max(0, Math.round(seconds || 0));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}
// The step the log is at, in words, from its last progress line.
function _dzJobPhase(J) {
  // Paused for ZIA's rate limit: count down to the moment it sends again.
  if (J && J.pausedEnd && J.status === 'running') {
    const left = (J.pausedEnd - Date.now()) / 1000;
    if (left > 0) {
      const at = new Date(J.pausedEnd).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
      return `Paused for ZIA's rate limit — resumes at ${at} (in ${_dzMMSS(left)}). Nothing is sent meanwhile; keep this window open.`;
    }
    return "ZIA's pause is over — sending again…";
  }
  const lines = (J && J.logs) || [];
  const steps = [
    [/^STOPPED/, 'Stopped — finishing activation and the read-back'],
    [/^Stop requested/, 'Stopping after the write in flight'],
    [/^Phase 1/, 'Step 1 of 5 — dictionaries'], [/^Phase 2b/, 'Step 2 of 5 — endpoint application groups'], [/^Phase 2/, 'Step 2 of 5 — engines'],
    [/^Phase 3/, 'Step 3 of 5 — rules on every channel'], [/^Phase 4/, 'Step 3 of 5 — confidence tweaks'],
    [/^Activating/, 'Step 4 of 5 — activating in ZIA and waiting for ACTIVE (up to 45 s)'], [/^Activation still/, 'Step 4 of 5 — still waiting for ZIA to report ACTIVE'],
    [/^Reading the tenant back|^Re-reading the tenant/, 'Step 5 of 5 — reading the tenant back to verify'], [/^Phase 5/, 'Step 5 of 5 — verifying'],
    [/refused for now; activating/, 'Waiting for ZIA to settle, then trying the refused deletes again'],
    [/\); waiting \d+s and trying again/, 'ZIA refused with a 403 — waiting and trying again (up to 5 times; about 7 minutes when ZIA answers Resource Access Blocked). Nothing is activated until the run is done'],
    [/ZIA allows \d+ .* waiting /, 'Waiting for the ZIA rate limit (the log says how long)'],
    [/pausing the whole run|rate limit is still resetting/, "Paused for ZIA's rate limit — the last log line says how long; nothing is sent meanwhile"],
  ];
  for (let i = lines.length - 1; i >= 0; i--) {
    for (const [re, text] of steps) if (re.test(lines[i])) return text;
    // A tenant read or a generation step names itself.
    if (/^(Reading the tenant|Generating |Gap mode|Static mode|Checking the approved plan|Tenant read in|Plan: |Ready: )/.test(lines[i])) return lines[i].replace(/…$/, '').trim();
  }
  return lines.length ? 'Working…' : 'Connecting to the tenant…';
}
function _dzJobUpdate(snap) {
  DZ.job = Object.assign(DZ.job || {}, snap);
  // The server says how many seconds the pause has left; count down from now.
  DZ.job.pausedEnd = snap.paused_seconds > 0 ? Date.now() + snap.paused_seconds * 1000 : null;
  const log = document.getElementById('dzJobLog');
  if (log) { log.textContent = (snap.logs || []).join('\n') || 'Connecting to the tenant…'; log.scrollTop = log.scrollHeight; }
  const ph = document.getElementById('dzJobPhase');
  if (ph) ph.textContent = _dzJobPhase(DZ.job);
  const el = document.getElementById('dzJobElapsed');
  if (el) el.textContent = _dzMMSS(snap.elapsed_seconds);
  const stop = document.getElementById('dzJobStop');
  if (stop && snap.cancel_requested) { stop.disabled = true; stop.textContent = 'Stopping…'; }
}
function _dzJobTick() {
  const J = DZ.job; if (!J || !J.startedAt) return;
  const el = document.getElementById('dzJobElapsed');
  if (el) el.textContent = _dzMMSS((Date.now() - J.startedAt) / 1000);
  if (J.pausedEnd) { const ph = document.getElementById('dzJobPhase'); if (ph) ph.textContent = _dzJobPhase(J); }
}
// A random name for one job start, sent as X-Start-Token.
function _dzNewStartToken() {
  try { if (window.crypto && crypto.randomUUID) return crypto.randomUUID().replace(/-/g, ''); } catch (e) { /* below */ }
  let t = ''; for (let i = 0; i < 4; i++) t += Math.random().toString(36).slice(2, 10).padEnd(8, '0');
  return t;
}
// Stop was asked for the job on screen, also before its id arrived.
function _dzStopAsked() {
  return !!((DZ.job && DZ.job.cancelRequested) || (DZ.pendingStart && DZ.pendingStart.stop));
}
async function _dzCancelJob() {
  const J = DZ.job;
  const btn = document.getElementById('dzJobStop');
  if (!J || !J.id) {
    // The start request is still signing in, so there is no job id yet.
    // The server is told by the start's token: the job begins stopped (or
    // is cancelled the moment it exists), so nothing is read or written.
    const P = DZ.pendingStart;
    if (!P || P.stop) return;
    P.stop = true;
    if (J) J.cancelRequested = true;
    if (btn) { btn.disabled = true; btn.textContent = 'Stopping…'; }
    try {
      await fetch('/api/dlp-packs/jobs/stop-before-start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ start_token: P.token }) });
    } catch (e) { /* the job is cancelled by id as soon as it arrives */ }
    announce('Stop requested before the run started. Nothing is read or written.');
    return;
  }
  if (J.cancelRequested) return;
  if (btn) { btn.disabled = true; btn.textContent = 'Stopping…'; }
  try { await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(J.id)}/cancel`, { method: 'POST' }); } catch (e) { /* the poll shows the state */ }
  J.cancelRequested = true;
  announce('Stop requested. The write in flight finishes; nothing more is sent.');
}
// Run a job end to end: start it, follow it, return the finished snapshot.
async function _dzRunJob(startUrl, body) {
  const pending = { token: _dzNewStartToken(), stop: false };
  DZ.pendingStart = pending;
  if (DZ.job && DZ.job.id) DZ.job = { logs: [] };   // a finished job's id must not take this run's Stop
  let id;
  try {
    id = await _dzStartJob(startUrl, body, pending.token);
  } finally {
    if (DZ.pendingStart === pending) DZ.pendingStart = null;
  }
  // A Stop pressed while the start was signing in carries over to the job,
  // which is also cancelled by id (the server may have started it already).
  DZ.job = { id, logs: [], startedAt: Date.now(), status: 'running', cancelRequested: pending.stop };
  if (pending.stop) {
    try { await fetch(`/api/dlp-packs/jobs/${encodeURIComponent(id)}/cancel`, { method: 'POST' }); } catch (e) { /* the token stopped it */ }
  }
  const tick = setInterval(_dzJobTick, 1000);
  try {
    return await _dzFollowJob(id, _dzJobUpdate);
  } finally {
    clearInterval(tick);
  }
}
function _dzJobLiveHtml(label) {
  const J = DZ.job || {};
  return `<div class="dz-log dz-log-live" id="dzJobLog" role="log" aria-live="polite" aria-label="${_dzE(label)}">${_dzE((J.logs || []).join('\n')) || 'Connecting to the tenant…'}</div>`;
}

// ── Step 3: approve ───────────────────────────────────────────────
function _dzRenderApprove() {
  const R = DZ.report;
  const items = R.items || [];
  const writes = items.filter(i => i.status === 'create' || i.status === 'modify' || i.status === 'restore');
  const restores = items.filter(i => i.status === 'restore');
  const warns = R.warnings || [];
  const body = document.getElementById('dzBody');
  body.innerHTML = `
    <div class="dz-hero">
      <span class="dz-status ${R.status}">${R.status === 'warnings' ? 'Review the warnings' : 'Ready'}</span>
      <div><div class="lead">${_dzN(writes.length, 'change')} to ${_dzE(R.tenant_label || 'your tenant')}</div>
      <div class="sub">${_dzN([...DZ.selected].length, 'pack')} · ${R.options.use_rank_0 ? 'rank 0 on' : 'standard ranking'} · ${R.options.apply_tweaks ? 'confidence tweaks on' : 'no confidence tweaks'}</div>
      <div class="sub">Channels — ${_dzTargetsSummary([...DZ.selected])}</div></div>
    </div>
    ${DZ.write && !DZ.write.enabled ? _dzWriteBanner() : ''}
    ${_dzRateCheck(R.rate_forecast, R.status === 'blocked')}
    ${warns.length ? `<div class="dz-h">Warnings<span class="count">${warns.length}</span></div><div class="dz-rows">${warns.map(w => `<div class="dz-row st-differs"><span class="ic" aria-hidden="true">!</span><div class="rs" style="margin-top:0.25rem;color:var(--text);">${_dzE(w)}</div><div></div></div>`).join('')}</div>` : ''}
    ${_dzSection('Exactly what will be written', writes)}
    <div class="dz-card sev-info"><div class="bar"></div><div><div class="t">Before you approve, confirm with the customer</div><div class="d">
      1. The tenant name above is the right tenant. &nbsp;2. The customer has seen this list and agreed. &nbsp;3. The customer knows the deploy activates the changes in ZIA when it completes (if activation cannot run, the result says so and an admin activates in the ZIA portal), and that every new rule arrives disabled.
      ${restores.length ? ' &nbsp;4. Converge mode is on: the objects listed above will be overwritten with the policy pack. If the customer changed any of them on purpose, stop and deploy without converge mode.' : ''}
    </div></div></div>
    <div class="dz-consent">
      <input type="checkbox" id="dzConsent" ${DZ.consent ? 'checked' : ''} onchange="DZ.consent=this.checked;_dzRenderApprove()">
      <label for="dzConsent">I've reviewed this plan and the warnings above, and I authorize these changes to <strong>${_dzE(R.tenant_label || 'the tenant')}</strong>. ${restores.length
        ? `<strong>${_dzN(restores.length, 'customized object')} will be overwritten</strong> with the policy pack definition (converge mode); every other existing object is left untouched.`
        : `Existing objects are not overwritten${_dzCounts(R).modify ? ` (${_dzN(_dzCounts(R).modify, 'confidence tweak')} on existing dictionaries, listed above as Will modify)` : ''}.`} The deploy activates the changes in ZIA when it completes.<br><code>plan ${_dzE((R.plan_hash || '').slice(0, 12))}</code></label>
    </div>`;
  const writeOff = DZ.write && !DZ.write.enabled;
  document.getElementById('dzFoot').innerHTML = `
    ${_dzGatesHtml(R, { step: 3 })}
    <div class="dz-summary" id="dzRdNote">${_dzReadinessBlocks('deploy_packs') ? _dzE(window.dlpReadiness.blockedNote('deploy_packs')) : writeOff ? 'The server is read-only: enable write mode to deploy.' : (DZ.consent ? 'Ready when you are.' : 'Tick the box to enable deployment.')}</div>
    <div class="dz-actions">
      <button type="button" class="dz-btn" onclick="DZ.step=2;_dzRender()">← Back</button>
      ${writeOff && DZ.write.can_toggle ? `<button type="button" class="dz-btn" onclick="_dzSetWriteMode(true)">Enable write mode</button>` : ''}
      <button type="button" class="dz-btn primary" ${_dzReadinessBlocks('deploy_packs') ? 'disabled aria-describedby="dzRdNote" ' : ''}${DZ.consent && R.status !== 'blocked' && !writeOff ? '' : 'disabled'} onclick="_dzApply()">Deploy to tenant</button>
    </div>`;
}

// ── Step 4: deploy ────────────────────────────────────────────────
// The rate-limit check as popup text: the verdict (sarcasm and all), the
// API plan and the success outlook.
function _dzRateText(f) {
  if (!f) return '';
  if (typeof window.zdRateText === 'function') return window.zdRateText(f);
  const when = f.run_after ? ` (${new Date(f.run_after * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} your time)` : '';
  return `Rate-limit check: ${f.title}\n${f.verdict}${when}\n\nAPI plan:\n${(f.plan || []).map(l => `  • ${l}`).join('\n')}\n\n${(f.success || {}).text || ''}`;
}

// The readiness check (static/readiness.js) says the API client's role cannot make this change.
function _dzReadinessBlocks(key) { return !!(window.dlpReadiness && window.dlpReadiness.isBlocked(key)); }

async function _dzApply() {
  if (window.dlpReadiness && !window.dlpReadiness.allowWrite('deploy_packs')) return;
  const f = (DZ.report || {}).rate_forecast;
  if (f && !window.confirm(`${_dzRateText(f)}\n\n${f.severity === 'ok' ? 'Deploy now?' : 'Deploy anyway?'} Click OK to deploy, or Cancel to stop.`)) return;
  DZ.step = 4; DZ.busy = true; DZ.result = null; DZ.error = ''; DZ.job = null;
  _dzRender();
  try {
    _dzNeedAssessor();
    const body = { pack_ids: [...DZ.selected], ...DZ.options, channel_targets: _dzTargets([...DZ.selected]), scopes: _dzRankScopes(), plan_hash: DZ.report.plan_hash, confirm: true, verify: true, ..._dzCreds() };
    const snap = await _dzRunJob('/api/dlp-packs/apply/start', body);
    if (snap.status === 'failed' || !snap.result) throw new Error(snap.error || 'The run ended without a result.');
    DZ.result = snap.result;
    if (!DZ.result.logs || !DZ.result.logs.length) DZ.result.logs = snap.logs;
    const s = DZ.result.summary || {};
    announce(`Deployment ${DZ.result.status}: ${s.created || 0} created, ${s.failed || 0} failed.`);
    try {
      localStorage.setItem('zassess_last_deploy', JSON.stringify({ at: new Date().toLocaleString(), status: DZ.result.status,
        created: s.created || 0, restored: s.restored || 0, failed: s.failed || 0, packs: [...DZ.selected] }));
    } catch (e) { /* storage unavailable */ }
  } catch (e) {
    DZ.error = e.message;
  } finally {
    DZ.busy = false; _dzRender();
  }
}

function _dzRenderDeploy() {
  const body = document.getElementById('dzBody');
  const foot = document.getElementById('dzFoot');
  if (DZ.busy) {
    const J = DZ.job || {};
    body.innerHTML = `
      <div class="dz-hero"><span class="dz-status busy">Deploying</span><div><div class="lead">Writing to ${_dzE((DZ.report || {}).tenant_label || 'tenant')}…</div><div class="sub" id="dzJobPhase">${_dzE(_dzJobPhase(J))}</div></div><div class="dz-elapsed" id="dzJobElapsed" aria-label="Elapsed">${_dzMMSS(J.startedAt ? (Date.now() - J.startedAt) / 1000 : 0)}</div></div>
      <div class="dz-progress"><div class="bar"></div></div>
      <div class="dz-card sev-info"><div class="bar"></div><div><div class="t">What is happening</div><div class="d">Dictionaries first, then engines, then rules on every channel — one answer from the tenant per line below. Then ZIA activates the changes, the app waits until ZIA reports ACTIVE (up to 45 seconds) and reads the tenant back to prove everything is there. A pack of 70 objects takes several minutes; each item is isolated, so one refusal never stops the rest. If the tenant refuses everything (someone holds the portal's edit lock, the hourly request limit is reached) the run stops at once and says why.</div></div></div>
      ${_dzJobLiveHtml('Deployment log')}`;
    foot.innerHTML = `<div class="dz-summary">Please keep this window open.</div><div class="dz-actions"><button type="button" class="dz-btn" id="dzJobStop" onclick="_dzCancelJob()" ${_dzStopAsked() ? 'disabled' : ''} title="Send nothing more after the write in flight; what was written is activated and recorded">${_dzStopAsked() ? 'Stopping…' : 'Stop'}</button><button class="dz-btn primary" disabled>Deploying…</button></div>`;
    return;
  }
  if (DZ.error) {
    body.innerHTML = `<div class="dz-card sev-error"><div class="bar"></div><div><div class="t">The deployment did not finish</div><div class="d">${_dzE(DZ.error)}</div></div></div>${(DZ.job && DZ.job.logs && DZ.job.logs.length) ? `<details class="dz-fold" open><summary><div class="dz-h">Log</div></summary><div class="dz-log">${_dzE(DZ.job.logs.join('\n'))}</div></details>` : ''}`;
    foot.innerHTML = `<div class="dz-summary"></div><div class="dz-actions"><button class="dz-btn" onclick="DZ.step=3;_dzRender()">← Back</button><button class="dz-btn primary" onclick="_dzRunPreflight()">Re-run preflight</button></div>`;
    return;
  }
  const X = DZ.result || {};
  if (X.status === 'plan_changed' || X.status === 'blocked') {
    body.innerHTML = `<div class="dz-card sev-warning"><div class="bar"></div><div><div class="t">${X.status === 'plan_changed' ? 'The tenant changed since you approved' : 'Deployment is blocked'}</div><div class="d">${_dzE(X.message || (X.blockers || []).join(' '))}</div><div class="d">Nothing was written. Run preflight again to see the current plan.</div></div></div>`;
    foot.innerHTML = `<div class="dz-summary"></div><div class="dz-actions"><button class="dz-btn primary" onclick="_dzRunPreflight()">Re-run preflight</button></div>`;
    return;
  }
  const s = X.summary || {};
  const results = X.results || [];
  const lead = X.stopped ? 'Deployment stopped early' : ({ applied: 'Deployed successfully', partial: 'Deployed with some failures', failed: 'Deployment failed' }[X.status] || X.status);
  const cls = X.stopped ? 'blocked' : ({ applied: 'ready', partial: 'warnings', failed: 'blocked' }[X.status] || 'warnings');
  const stoppedCard = X.stopped ? `<div class="dz-card sev-high" style="margin-top:0.9rem;"><div class="bar"></div><div><div class="t">Why it stopped</div><div class="d">${_dzE(X.stopped)} Everything that was already written is activated and recorded; the objects listed as skipped were never sent. Run the same deployment again when ready: only what is missing will be created.</div></div></div>` : '';
  const ver = X.verification || {};
  const verRows = Object.entries(ver).map(([id, v]) => {
    const ok = v && v.all_good;
    const d = v.dictionaries || {}, e = v.engines || {};
    const detail = v.error ? v.error : `dictionaries ${d.ok ?? '?'}/${d.total ?? '?'}, engines ${e.ok ?? '?'}/${e.total ?? '?'}${(d.missing || []).length ? `; missing: ${d.missing.join(', ')}` : ''}${Object.keys(d.mismatched || {}).length ? `; mismatched: ${Object.keys(d.mismatched).join(', ')}` : ''}`;
    return _dzRow({ name: id, kind: 'policy', packs: [] }, ok ? 'created' : 'failed', (ok ? 'Verified — tenant matches the pack. ' : 'Verification found differences. ') + detail).replace('kind-policy">Policy', 'kind-policy">Pack');
  }).join('');
  const rc = X.read_check || null;
  const readCard = !rc ? '' : (rc.error || !rc.read
    ? `<div class="dz-card sev-warning" style="margin-top:0.9rem;"><div class="bar"></div><div><div class="t">Not read back</div><div class="d">The tenant could not be read again after the deployment${rc.error ? ` (${_dzE(rc.error)})` : ''}. Run <strong>Where is this tenant?</strong> on the pack card to check what exists.</div></div></div>`
    : (rc.clean
      ? `<div class="dz-card sev-info" style="margin-top:0.9rem;"><div class="bar"></div><div><div class="t">Verified by a fresh read: all ${rc.present} object(s) are in the tenant</div><div class="d">After activation${rc.activation_status ? ` (ZIA status ${_dzE(rc.activation_status)})` : ''} the same preflight was run again and found every dictionary, engine and rule this deployment created or reused.</div></div></div>`
      : `<div class="dz-card sev-high" style="margin-top:0.9rem;"><div class="bar"></div><div><div class="t">Read back: ${rc.missing.length} of ${rc.expected} object(s) not found</div><div class="d">A fresh read after activation${rc.activation_status ? ` (ZIA status ${_dzE(rc.activation_status)})` : ''} could not find these. If the status is not ACTIVE, activate in ZIA and re-run the preflight; otherwise deploy again — only what is missing will be created.</div></div></div>
         <div class="dz-rows">${rc.missing.map(m => `<div class="dz-row st-fail"><span class="ic">!</span><div><div class="nm">${_dzE(DZ_KIND[m.kind] || m.kind)}: ${_dzE(m.name)}${m.channel ? ` <span class="dz-chip kind-channel">${_dzE(_dzChan(m.channel))}</span>` : ''}</div><div class="rs">${_dzE(m.reason || '')}</div></div></div>`).join('')}</div>`));
  body.innerHTML = `
    <div class="dz-hero"><span class="dz-status ${cls}">${lead}</span><div><div class="lead">${_dzN(s.created || 0, 'object')} created${s.restored ? ` · ${s.restored} overwritten` : ''} · ${s.modified || 0} modified · ${s.reused || 0} reused · ${s.skipped || 0} skipped · ${s.failed || 0} failed</div><div class="sub">${_dzMMSS(X.elapsed_seconds || 0)} min</div></div></div>
    ${stoppedCard}
    ${readCard}
    ${Object.keys(X.channels || {}).length ? `<div class="dz-card ${Object.values(X.channels).some(c => c.failed) ? 'sev-high' : 'sev-info'}" style="margin-top:0.9rem;"><div class="bar"></div><div><div class="t">Rules per channel</div><div class="d">${Object.entries(X.channels).map(([ch, c]) => `<div><strong>${_dzE(_dzChan(ch))}</strong>: ${c.created} created${c.restored ? `, ${c.restored} overwritten` : ''}${c.reused ? `, ${c.reused} reused` : ''}${c.skipped ? `, ${c.skipped} skipped` : ''}${c.failed ? `, <strong>${c.failed} failed</strong>${c.errors.length ? ` — ${_dzE(c.errors.join(' | '))}` : ''}` : ''}</div>`).join('')}</div></div></div>` : ''}
    ${X.activation && X.activation.activated ? `<div class="dz-card sev-info" style="margin-top:0.9rem;"><div class="bar"></div><div><div class="t">Activated in ZIA</div><div class="d">The changes were activated automatically, so they are live now.</div></div></div>` : ''}
    ${X.activation_required ? `<div class="dz-card sev-warning" style="margin-top:0.9rem;"><div class="bar"></div><div><div class="t">Activate to take effect</div><div class="d">ZIA saved these changes as pending and automatic activation did not run${X.activation && X.activation.error ? ` (${_dzE(X.activation.error)})` : ''}. Open the ZIA Admin Portal and click Activate (or run ziaActivator) — users are unaffected until you do.</div></div></div>` : ''}
    <div class="dz-card sev-info"><div class="bar"></div><div><div class="t">What to do next</div><div class="d">
      <ol class="dz-next">
        <li><strong>Activation</strong> ran automatically and the tenant was read back (see above); if the read found gaps, activate in the ZIA Admin Portal and re-run the preflight.</li>
        <li><strong>Enable rules one at a time</strong> in Policy &gt; Data Loss Prevention, starting with the monitor-only ones, and raise their severity once incidents look right.</li>
        <li><strong>Review incidents</strong> after a few days, then tune. Changes the customer makes in the portal are kept; fold the good ones back into the pack so the next tenant starts from them.</li>
        <li><strong>Measure the journey</strong> on the next visit: run the assessment, or click <em>Where is this tenant?</em> on the pack card. It shows the stage reached (Foundation → Policies deployed → Visibility → Containment → Enforcement) and exactly which rules to enable or harden next.</li>
        <li>If the customer manages Zscaler with Terraform, use <strong>Hand off as Terraform</strong> on the review step to hand them the same configuration with state.</li>
      </ol></div></div></div>
    ${_dzSection('Failed', results.filter(r => r.status === 'failed'), { fn: r => _dzRow(r, 'failed', r.explanation ? `${r.error} — What this means: ${r.explanation}` : r.error) })}
    ${_dzSection('Overwritten with the policy pack (converge mode)', results.filter(r => r.status === 'restored'), { fn: r => _dzRow(r, 'restored', `${r.id ? `ID ${r.id}` : ''}${r.drift && r.drift.length ? ` · ${r.drift.join(', ')}` : ''}`) })}
    ${_dzSection('Created & modified', results.filter(r => r.status === 'created' || r.status === 'modified'), { fn: r => _dzRow(r, r.status, r.id ? `ID ${r.id}` : '') })}
    ${_dzSection('Skipped', results.filter(r => r.status === 'skipped'), { fn: r => _dzRow(r, 'skipped', r.reason) })}
    ${_dzSection('Reused from tenant', results.filter(r => r.status === 'reused'), { open: false, fn: r => _dzRow(r, 'reused', r.id ? `ID ${r.id}` : '') })}
    ${verRows ? `<div class="dz-h">Post-deploy verification</div><div class="dz-rows">${verRows}</div>` : ''}
    ${(X.logs || []).length ? `<details class="dz-fold"><summary><div class="dz-h">Log</div></summary><div class="dz-log">${_dzE(X.logs.join('\n'))}</div></details>` : ''}`;
  _dzFlowSyncTab((DZ.report || {}).items || [], results);   // the standalone flow page, if open, follows the result
  foot.innerHTML = `
    <div class="dz-summary">plan ${_dzE((X.plan_hash || '').slice(0, 12))}${X.deployment_id ? ' · recorded for undo' : ''}${X.deployment_error ? ` · ${_dzE(X.deployment_error)}` : ''}</div>
    <div class="dz-actions">
      ${X.deployment_id ? `<button type="button" class="dz-btn" title="Delete everything this deployment just created" onclick="_dzUndoLast()">Undo this deployment</button>` : ''}
      <button type="button" class="dz-btn" onclick="DZ.step=1;DZ.report=null;DZ.result=null;_dzRender()">Deploy more</button>
      <button type="button" class="dz-btn primary" onclick="closeDlpPacksModal()">Done</button>
    </div>`;
}


// ── Remove rules — a wizard that mirrors deploy ───────────────────
// Select (every rule in the tenant, ticked by the operator) -> Preview (the
// check: which rules go, which engines and dictionaries follow because
// nothing else uses them, which are kept and why) -> Approve (the exact
// list, a consent box, a final confirmation) -> Remove (usage checked
// again right before each engine and dictionary) -> Verify (a fresh read).
// The same wizard undoes a recorded deployment. Whole-pack removal is no
// longer offered: the picker's "Select Zscaler Made Easy rules" covers it with the
// same checks.
const RM_KIND = { policy: 'rule', app_group: 'application group', engine: 'engine', dictionary: 'dictionary' };
const RM_STEPS = ['Preview', 'Approve', 'Remove', 'Verify'];

const RM_ALL = '__all__';

// id is one pack id, or RM_ALL to find and remove what EVERY pack in the
// library put in the tenant, in one plan and one pass.
// Every removal — a pack, everything, picked rules, or the undo of one
// deployment — enters the same wizard: Preview → Approve → Remove → Verify.
// `id` is a pack id, RM_ALL, or { deployment: <record> } for an undo.
async function _dzRemove(id) {
  const dep = id && typeof id === 'object' ? id.deployment : null;
  const key = dep ? `dep:${dep.id}` : id;
  const all = id === RM_ALL;
  const ids = dep ? [] : (all ? (DZ.packs || []).map(x => x.id) : [id]);
  const pack = dep
    ? { id: dep.id, name: `the deployment of ${(dep.packs || []).join(', ')} on ${new Date(dep.at).toLocaleString()}` }
    : (all ? { id: RM_ALL, name: 'every deployed policy pack' } : ((DZ.packs || []).find(x => x.id === id) || { id, name: id }));
  DZ.remove = DZ.remove || {}; DZ.remove[key] = 'busy'; if (dep) DZ.undoBusy = dep.id; _dzRenderSelect();
  let plan;
  try {
    const r = await fetch('/api/dlp-packs/removal/preflight', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(dep ? { pack_ids: [], deployment_id: dep.id, ..._dzCreds() } : { pack_ids: ids, all, ..._dzCreds() }),
    });
    plan = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((plan.detail && (plan.detail.cause || plan.detail)) || `HTTP ${r.status}`);
  } catch (e) {
    DZ.remove[key] = null; DZ.undoBusy = null; _dzRenderSelect();
    alert(`Could not scan the tenant for ${pack.name || id}: ${e.message}`);
    return;
  }
  DZ.remove[key] = null; DZ.undoBusy = null;
  if (plan.status === 'blocked') { alert((plan.blockers || ['Could not read the tenant.']).join('\n')); _dzRenderSelect(); return; }
  DZ.removal = { id: dep ? dep.id : id, ids, mode: dep ? 'deployment' : undefined, deployment: dep || null, pack, plan, step: 1, result: null };
  _dzRemovalRender();
}

function _dzRemovalClose() { DZ.removal = null; DZ.step = 1; _dzRender(); }

// One sentence on what the removal preview could see, for the "nothing to
// remove" card: counts per kind, how many carry a Zscaler Made Easy tag, and what
// could not be listed.
function _dzReadSummary(rd) {
  if (!rd) return '';
  const rules = Object.entries(rd.rules || {}).map(([ch, n]) => `${_dzChan(ch)} ${n}`).join(', ');
  const parts = [`${rd.dictionaries} dictionaries (${rd.custom_dictionaries} custom, ${rd.tagged_dictionaries} tagged by Zscaler Made Easy)`,
                 `${rd.engines} engines (${rd.tagged_engines} tagged)`, `rules: ${rules || 'none'} (${rd.tagged_rules} tagged)`];
  const bad = Object.entries(rd.unreadable || {}).map(([k, v]) => `${k} could not be listed (${v})`)
    .concat(Object.entries(rd.channel_errors || {}).map(([k, v]) => `${_dzChan(k)} rules could not be listed (${v})`));
  return parts.join('; ') + (bad.length ? '. ' + bad.join('; ') + '.' : '.');
}

function _dzRemovalRender() {
  const R = DZ.removal; if (!R) return;
  const pick = R.mode === 'pick';
  const names = pick ? ['Select', ...RM_STEPS] : RM_STEPS;
  const base = pick ? 0 : 1;
  // The sheet is a removal now: its title, its step strip and its footer say so
  // (the deploy footer with Run preflight must never show under a removal).
  document.getElementById('dzTitle').textContent = pick ? 'Remove rules' : (R.mode === 'deployment' ? 'Undo a deployment' : `Remove ${(R.pack && R.pack.name) || 'the pack'}`);
  const steps = document.getElementById('dzSteps');
  steps.setAttribute('aria-label', 'Removal steps');
  steps.innerHTML = names.map((s, i) => {
    const n = base + i, cls = n === R.step ? 'is-active' : (n < R.step ? 'is-done' : '');
    return `<div class="dz-step ${cls}" ${n === R.step ? 'aria-current="step"' : ''}><span class="n">${n < R.step ? '✓' : i + 1}</span>${s}</div>`;
  }).join('');
  const subs = { 0: `Every DLP rule in ${_dzE((R.inventory && R.inventory.tenant_label) || 'the tenant')} on every channel. Tick the leftovers; their engines and dictionaries follow, unless something else still uses them. Nothing is deleted yet.`,
                 1: `The check before anything goes: which rules, which engines and dictionaries follow them, and what is kept because something else in ${_dzE((R.plan && R.plan.tenant_label) || 'the tenant')} still uses it. Nothing is deleted yet.`,
                 2: 'Review the exact list, then approve. Deletion runs rules → activate → engines → activate → dictionaries → activate, and needs write mode.',
                 3: 'Removing tier by tier (rules, then engines, then dictionaries), activating after each and waiting for ZIA to report ACTIVE — keep this window open.',
                 4: 'Verified by a fresh read of the tenant after activation.' };
  document.getElementById('dzSub').textContent = subs[R.step];
  ({ 0: _dzRemovalSelect, 1: _dzRemovalPreview, 2: _dzRemovalApprove, 3: _dzRemovalBusy, 4: _dzRemovalDone })[R.step]();
}

// The request body that identifies what this wizard removes: the packs,
// everything, or the rules the operator picked.
function _dzRemovalScope() {
  const R = DZ.removal;
  if (R.mode === 'pick') return { pack_ids: [], rules: R.rules || [] };
  if (R.mode === 'deployment') return { pack_ids: [], deployment_id: R.id };
  return { pack_ids: R.ids || [R.id], all: R.id === RM_ALL };
}

const RM_PICK = '__pick__';

// Pick mode: list every DLP rule the tenant has, let the operator tick
// the leftovers, and plan their removal with the engines and
// dictionaries only they use.
async function _dzRemovePick() {
  DZ.remove = DZ.remove || {}; DZ.remove[RM_PICK] = 'busy'; _dzRenderSelect();
  let inv;
  try {
    const r = await fetch('/api/dlp-packs/removal/inventory', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ..._dzCreds(), ..._dzScope() }) });
    inv = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((inv.detail && (inv.detail.cause || inv.detail)) || `HTTP ${r.status}`);
  } catch (e) {
    DZ.remove[RM_PICK] = null; _dzRenderSelect();
    alert(`Could not list the tenant's DLP rules: ${e.message}`);
    return;
  }
  DZ.remove[RM_PICK] = null;
  if (inv.status === 'blocked') { alert((inv.blockers || ['Could not read the tenant.']).join('\n')); _dzRenderSelect(); return; }
  DZ.removal = { id: RM_PICK, mode: 'pick', pack: { id: RM_PICK, name: 'the selected rules' }, inventory: inv, selected: new Set(), filter: '', plan: null, step: 0, result: null };
  _dzRemovalRender();
}

function _dzRemovalSelect() {
  const R = DZ.removal, body = document.getElementById('dzBody');
  const rules = (R.inventory.rules || []);
  const key = r => `${r.channel}:${r.id}`;
  const q = (R.filter || '').toLowerCase();
  const shown = rules.filter(r => !q || (r.name || '').toLowerCase().includes(q) || (r.engines || []).join(' ').toLowerCase().includes(q) || (r.pack || '').toLowerCase().includes(q));
  const byChan = {};
  shown.forEach(r => { (byChan[r.channel] = byChan[r.channel] || []).push(r); });
  const row = r => `<label class="dz-row dz-pick ${R.selected.has(key(r)) ? 'on' : ''}">
      <input type="checkbox" ${R.selected.has(key(r)) ? 'checked' : ''} onchange="_dzPickToggle('${_dzE(key(r))}', this.checked)" aria-label="Remove ${_dzE(r.name)}">
      <div><div class="nm">${_dzE(r.name)} <span class="dz-chip ${String(r.state).toUpperCase() === 'ENABLED' ? 'kind-policy' : ''}">${_dzE(String(r.state || '').toLowerCase() || 'state ?')}</span>${r.parent_id != null ? '<span class="dz-chip">sub-rule</span>' : ''}</div>
        <div class="rs">${r.tagged ? `Zscaler Made Easy · ${_dzE(r.pack || 'pack')}` : 'not created by Zscaler Made Easy'}${(r.engines || []).length ? ` · engines: ${_dzE(r.engines.slice(0, 4).join(', '))}${r.engines.length > 4 ? '…' : ''}` : ' · no engines'}${r.action ? ` · ${_dzE(String(r.action).toLowerCase())}` : ''}</div></div>
    </label>`;
  const groups = Object.keys(byChan).map(ch => `<div class="dz-h" style="margin-top:0.8rem;">${_dzE(_dzChan(ch))}<span class="count">${byChan[ch].length}</span></div><div class="dz-rows">${byChan[ch].map(row).join('')}</div>`).join('');
  // Orphans: engines no rule uses and dictionaries no engine uses. Nothing
  // reaches them through a rule, so they are offered here on their own.
  const orph = R.inventory.orphans || {};
  const oEng = (orph.engines || []).filter(e => !q || (e.name || '').toLowerCase().includes(q) || (e.pack || '').toLowerCase().includes(q));
  const oDict = (orph.dictionaries || []).filter(d => !q || (d.name || '').toLowerCase().includes(q) || (d.pack || '').toLowerCase().includes(q));
  const orow = (o, what) => { const k = `${o.kind}:${o.id}`; return `<label class="dz-row dz-pick ${R.selected.has(k) ? 'on' : ''}">
      <input type="checkbox" ${R.selected.has(k) ? 'checked' : ''} onchange="_dzPickToggle('${_dzE(k)}', this.checked)" aria-label="Remove ${_dzE(o.name)}">
      <div><div class="nm">${_dzE(o.name)} <span class="dz-chip">${what}</span></div>
        <div class="rs">${o.tagged ? `Zscaler Made Easy · ${_dzE(o.pack || 'pack')}` : 'not created by Zscaler Made Easy'}${o.kind === 'engine' ? ' · no rule on any channel uses it' + ((o.dictionaries || []).length ? ` · dictionaries: ${_dzE(o.dictionaries.slice(0, 4).join(', '))}${o.dictionaries.length > 4 ? '…' : ''}` : '') : ' · no engine uses it'}</div>${o.kind === 'engine' ? _dzEngineExplain(o) : ''}</div>
    </label>`; };
  const orphanGroups = (oEng.length ? `<div class="dz-h" style="margin-top:0.8rem;">Engines with no rule<span class="count">${oEng.length}</span></div><div class="dz-rows">${oEng.map(o => orow(o, 'engine')).join('')}</div>` : '')
    + (oDict.length ? `<div class="dz-h" style="margin-top:0.8rem;">Dictionaries no engine uses<span class="count">${oDict.length}</span></div><div class="dz-rows">${oDict.map(o => orow(o, 'dictionary')).join('')}</div>` : '');
  const nOrph = (orph.engines || []).length + (orph.dictionaries || []).length;
  const errs = Object.entries(R.inventory.errors || {}).filter(([, v]) => v);
  body.innerHTML = `
    <div class="dz-card sev-info"><div class="bar"></div><div><div class="t">${rules.length} DLP rule(s) in the tenant${nOrph ? `, plus ${_dzN(nOrph, 'orphan')} (an engine no rule uses, or a dictionary no engine uses)` : ''}</div>
      <div class="d">Tick the leftovers to remove. The plan then adds the engines and dictionaries only those rules use; anything an unticked rule or a surviving engine still uses is kept and listed. Orphan engines and dictionaries are listed at the bottom so a leftover with no rule can go too. Predefined objects are never touched.${errs.length ? ` Not listed: ${_dzE(errs.map(([k, v]) => `${_dzChan(k)} (${v})`).join('; '))}.` : ''}</div></div></div>
    <div class="dz-pick-tools">
      <input type="search" class="dz-input" placeholder="Filter by rule, engine or pack" value="${_dzE(R.filter || '')}" oninput="_dzRefilter(DZ.removal, this, _dzRemovalRender)" aria-label="Filter rules">
      <button type="button" class="dz-link" onclick="_dzPickSet(r => r.tagged)">Select Zscaler Made Easy rules</button>
      <button type="button" class="dz-link" onclick="_dzPickSet(r => String(r.state).toUpperCase() !== 'ENABLED')">Select disabled rules</button>
      <button type="button" class="dz-link" onclick="_dzPickSet(() => true)">Select all shown</button>
      <button type="button" class="dz-link" onclick="_dzPickSet(() => false)">Clear</button>
    </div>
    ${groups || '<div class="dz-empty">No rules match the filter.</div>'}
    ${orphanGroups}`;
  document.getElementById('dzFoot').innerHTML = `
    <div class="dz-summary">${R.selected.size
      ? `<strong style="color:var(--text);">${_dzN(R.selected.size, 'item')}</strong> ticked. The preview adds the engines and dictionaries only they use, and writes nothing.`
      : 'Tick at least one rule, engine or dictionary to continue. Nothing is deleted yet.'}</div>
    <div class="dz-actions">
      <button type="button" class="dz-btn quiet" onclick="_dzRemovalClose()">Cancel</button>
      <button type="button" class="dz-btn primary" onclick="_dzRemovalPickPreview()" ${R.selected.size && !DZ.busy ? '' : 'disabled'}>${DZ.busy ? 'Planning…' : `Preview removal of ${R.selected.size} item(s)`}</button>
    </div>`;
}

// A rule filter re-renders the whole sheet, which replaces the box being
// typed in. Put focus and the caret back in the new box so typing goes on.
function _dzRefilter(state, input, render) {
  if (!state) return;
  const at = input.selectionStart;
  state.filter = input.value;
  render();
  const box = document.querySelector('#dzBody input[aria-label="Filter rules"]');
  if (!box) return;
  box.focus();
  try { const n = at == null ? box.value.length : at; box.setSelectionRange(n, n); } catch (e) { /* some input types refuse a selection */ }
}
function _dzPickToggle(k, on) { const R = DZ.removal; if (!R) return; if (on) R.selected.add(k); else R.selected.delete(k); _dzRemovalRender(); }
function _dzPickSet(pred) {
  const R = DZ.removal; if (!R) return;
  const q = (R.filter || '').toLowerCase();
  (R.inventory.rules || []).forEach(r => {
    const vis = !q || (r.name || '').toLowerCase().includes(q) || (r.engines || []).join(' ').toLowerCase().includes(q) || (r.pack || '').toLowerCase().includes(q);
    if (!vis) return;
    const k = `${r.channel}:${r.id}`;
    if (pred(r)) R.selected.add(k); else R.selected.delete(k);
  });
  const orph = R.inventory.orphans || {};
  [...(orph.engines || []), ...(orph.dictionaries || [])].forEach(o => {
    const vis = !q || (o.name || '').toLowerCase().includes(q) || (o.pack || '').toLowerCase().includes(q);
    if (!vis) return;
    const k = `${o.kind}:${o.id}`;
    if (pred({ ...o, state: 'DISABLED' })) R.selected.add(k); else R.selected.delete(k);
  });
  _dzRemovalRender();
}

async function _dzRemovalPickPreview() {
  const R = DZ.removal; if (!R || !R.selected.size || DZ.busy) return;
  const orph = R.inventory.orphans || {};
  R.rules = (R.inventory.rules || []).filter(r => R.selected.has(`${r.channel}:${r.id}`)).map(r => ({ channel: r.channel, id: r.id }))
    .concat([...(orph.engines || []), ...(orph.dictionaries || [])].filter(o => R.selected.has(`${o.kind}:${o.id}`)).map(o => ({ kind: o.kind, id: o.id })));
  DZ.busy = true; _dzRemovalRender();
  try {
    const r = await fetch('/api/dlp-packs/removal/preflight', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pack_ids: [], rules: R.rules, ..._dzCreds() }) });
    const plan = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((plan.detail && (plan.detail.cause || plan.detail)) || `HTTP ${r.status}`);
    plan.tenant_label = plan.tenant_label || R.inventory.tenant_label;
    R.plan = plan; R.step = 1;
  } catch (e) {
    alert(`Could not plan the removal: ${e.message}`);
  } finally { DZ.busy = false; _dzRemovalRender(); }
}

function _dzRemovalPreview() {
  const R = DZ.removal, body = document.getElementById('dzBody');
  const items = R.plan.items || [];
  const remove = items.filter(i => i.status === 'remove');
  const keep = items.filter(i => i.status === 'keep');
  const order = { policy: 0, app_group: 1, engine: 2, dictionary: 3 };
  const row = i => `<div class="dz-row ${i.status === 'keep' ? 'st-reuse' : 'st-fail'}">
    <span class="ic" aria-hidden="true">${i.status === 'keep' ? '↺' : '🗑'}</span>
    <div><div class="nm">${_dzE(RM_KIND[i.kind] || i.kind)}: ${_dzE(i.name)}${i.channel ? ` <span class="dz-chip kind-channel">${_dzE(_dzChan(i.channel))}</span>` : ''}</div>
      <div class="rs">${i.status === 'keep' ? `Kept — ${_dzE(i.keep)}` : (i.match === 'name' ? 'Removed — matched by name (no Zscaler Made Easy tag; confirm it is yours)' : 'Removed — carries this pack’s Zscaler Made Easy tag')}</div></div>
  </div>`;
  const removeSorted = remove.slice().sort((a, b) => (order[a.kind] ?? 9) - (order[b.kind] ?? 9) || a.name.localeCompare(b.name));
  body.innerHTML = `
    ${!remove.length ? `<div class="dz-card sev-info"><div class="bar"></div><div><div class="t">Nothing to remove</div><div class="d">No objects in the tenant carry this pack’s Zscaler Made Easy tag or its names.${keep.length ? ` ${keep.length} matching object(s) are kept because something else still uses them.` : ''}</div>
      ${R.plan.read ? `<div class="d" style="margin-top:0.4rem;">What the preview read from ${_dzE(R.plan.tenant_label || 'the tenant')}: ${_dzE(_dzReadSummary(R.plan.read))}</div>` : ''}
      ${(R.plan.warnings || []).length ? `<div class="d" style="margin-top:0.4rem;">${(R.plan.warnings || []).map(w => `⚠ ${_dzE(w)}`).join('<br>')}</div>` : ''}</div></div>` : `
    <div class="dz-card sev-info"><div class="bar"></div><div><div class="t">What was checked</div><div class="d">Every DLP rule on every channel of ${_dzE(R.plan.tenant_label || 'the tenant')} and every engine were read. An engine goes only when no rule outside this selection uses it; a dictionary goes only when no engine that stays uses it; predefined Zscaler objects are never touched. ${_dzN(remove.filter(i => i.kind === 'policy').length, 'rule')}, ${_dzN(remove.filter(i => i.kind === 'engine').length, 'engine')} and ${_dzN(remove.filter(i => i.kind === 'dictionary').length, 'dictionary', 'dictionaries')} will be removed; ${_dzN(keep.length, 'object')} kept. The same usage check runs again right before each engine and dictionary is deleted.</div></div></div>
    ${_dzRateCheck(R.plan.rate_forecast, R.plan.status === 'blocked')}
    <div class="dz-h" style="margin-top:1rem;">Will remove<span class="count">${remove.length}</span></div>
    <div class="dz-rows">${removeSorted.map(row).join('')}</div>
    ${keep.length ? `<div class="dz-h" style="margin-top:1rem;">Kept (still used elsewhere)<span class="count">${keep.length}</span></div><div class="dz-rows">${keep.map(row).join('')}</div>` : ''}`}`;
  document.getElementById('dzFoot').innerHTML = `
    <div class="dz-summary">${remove.length
      ? `<strong style="color:var(--text);">${_dzN(remove.length, 'object')}</strong> will be removed · ${_dzN(keep.length, 'object')} kept. Nothing is deleted yet.`
      : 'Nothing to remove.'}</div>
    <div class="dz-actions">
      <button type="button" class="dz-btn quiet" onclick="_dzRemovalClose()">Cancel</button>
      ${R.mode === 'pick' ? '<button type="button" class="dz-btn quiet" onclick="DZ.removal.step=0;_dzRemovalRender()">Back to the rules</button>' : ''}
      <button type="button" class="dz-btn quiet" onclick="_dzRemovalReport()" ${remove.length ? '' : 'disabled'}>Print or save as PDF</button>
      <button type="button" class="dz-btn primary" onclick="DZ.removal.step=2;_dzRemovalRender()" ${remove.length ? '' : 'disabled'}>Continue to approve</button>
    </div>`;
}

function _dzRemovalApprove() {
  const R = DZ.removal, body = document.getElementById('dzBody');
  const remove = (R.plan.items || []).filter(i => i.status === 'remove');
  const keep = (R.plan.items || []).filter(i => i.status === 'keep');
  const nameOnly = remove.filter(i => i.match === 'name');
  const writeOn = !!(DZ.write && DZ.write.enabled);
  const byKind = k => remove.filter(i => i.kind === k);
  const list = (items, label) => items.length ? `<div class="dz-h" style="margin-top:0.8rem;">${label}<span class="count">${items.length}</span></div><div class="dz-rows">${items.map(i => `<div class="dz-row st-fail"><span class="ic" aria-hidden="true">🗑</span><div><div class="nm">${_dzE(i.name)}${i.channel ? ` <span class="dz-chip kind-channel">${_dzE(_dzChan(i.channel))}</span>` : ''}</div>${i.kind !== 'policy' ? `<div class="rs">${i.match === 'selected' ? 'picked on its own' : 'nothing else uses it once the rules above are gone'}</div>` : ''}</div></div>`).join('')}</div>` : '';
  body.innerHTML = `
    ${_dzWriteBanner()}
    <div class="dz-card sev-high"><div class="bar"></div><div>
      <div class="t">Remove ${_dzN(byKind('policy').length, 'rule')}, ${_dzN(byKind('engine').length, 'engine')} and ${_dzN(byKind('dictionary').length, 'dictionary', 'dictionaries')} from ${_dzE(R.plan.tenant_label || 'the tenant')}</div>
      <div class="d">Deleted in dependency order: rules, then endpoint application groups, then engines, then dictionaries — activating between tiers so ZIA no longer counts the engines and dictionaries as referenced. Right before each engine and dictionary is deleted the tenant is read again: if a rule or engine now uses it, it is left alone and said so. ${keep.length ? `${_dzN(keep.length, 'object')} already kept because something else uses ${keep.length === 1 ? 'it' : 'them'}.` : ''} Activation runs automatically.</div>
    </div></div>
    ${list(byKind('policy'), 'Rules to remove')}
    ${list(byKind('app_group'), 'Endpoint application groups to remove')}
    ${list(byKind('engine'), 'Engines to remove')}
    ${list(byKind('dictionary'), 'Dictionaries to remove')}
    ${nameOnly.length ? `<div class="dz-card sev-medium"><div class="bar"></div><div><div class="t">${nameOnly.length} object(s) matched by name only</div><div class="d">These carry no Zscaler Made Easy tag: ${_dzE(nameOnly.map(i => i.name).join(', '))}. Confirm they are yours before removing.</div></div></div>` : ''}
    <label class="dz-consent"><input type="checkbox" id="rmConsent" ${R.consent ? 'checked' : ''} onchange="DZ.removal.consent=this.checked;_dzRemovalRender()"> I have read the list above and I authorize the permanent removal of these ${remove.length} object(s) from ${_dzE(R.plan.tenant_label || 'the tenant')}.</label>`;
  document.getElementById('dzFoot').innerHTML = `
    <div class="dz-summary">${!writeOn ? ((DZ.write || {}).can_toggle ? 'The server is read-only: click Enable write mode (you will type the confirmation phrase), then Remove now unlocks.' : _dzE((DZ.write || {}).reason || ('The server is read-only and write mode cannot be enabled from here; ' + ((DZ.write || {}).how_to_enable || 'start it with ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND') + '.'))) : (R.consent ? 'Ready: Remove now deletes the objects above and verifies by a fresh read.' : 'Tick the box to enable Remove now.')}</div>
    <div class="dz-actions">
      <button type="button" class="dz-btn quiet" onclick="DZ.removal.step=1;_dzRemovalRender()">Back</button>
      <button type="button" class="dz-btn quiet" onclick="_dzRemovalReport()">Print or save as PDF</button>
      ${!writeOn && (DZ.write || {}).can_toggle ? `<button type="button" class="dz-btn" onclick="_dzSetWriteMode(true)">Enable write mode</button>` : ''}
      ${R.mode === 'pick' && R.plan.plan_hash && remove.length ? `<button type="button" class="dz-btn" id="dzRequestRemovalApproval" title="File this removal plan in the change queue for another writer to approve. Nothing is removed now." onclick="_dzRequestApproval('removal')">Request approval</button>` : ''}
      <button type="button" class="dz-btn danger" ${writeOn && R.consent ? '' : 'disabled'} title="${writeOn ? '' : 'Enable write mode first'}" onclick="_dzRemovalApply()">Remove now</button>
    </div>${_dzRequestedHtml(R.plan.plan_hash)}`;
}

function _dzRemovalBusy() {
  const R = DZ.removal, body = document.getElementById('dzBody');
  const n = (R.plan.items || []).filter(i => i.status === 'remove').length;
  const J = DZ.job || {};
  body.innerHTML = `
    <div class="dz-hero"><span class="dz-status busy">Removing</span><div><div class="lead">Removing ${n} object(s) from ${_dzE(R.plan.tenant_label || 'the tenant')}…</div><div class="sub" id="dzJobPhase">${_dzE(_dzJobPhase(J))}</div></div><div class="dz-elapsed" id="dzJobElapsed" aria-label="Elapsed">${_dzMMSS(J.startedAt ? (Date.now() - J.startedAt) / 1000 : 0)}</div></div>
    <div class="dz-progress"><div class="bar"></div></div>
    <div class="dz-card sev-info"><div class="bar"></div><div>
      <div class="t">What is happening</div>
      <div class="d">Rules first, then activate; engines, then activate; dictionaries, then activate — waiting for ZIA to report ACTIVE after each activation (up to 45 seconds), because ZIA refuses to delete an engine while a rule that uses it is only pending deletion. When the last activation has settled the tenant is read again to prove nothing of the pack is left. Each line below is one answer from the tenant; a few minutes is normal.</div></div></div>
    ${_dzJobLiveHtml('Removal log')}`;
  document.getElementById('dzFoot').innerHTML = `<div class="dz-summary">Please keep this window open.</div><div class="dz-actions"><button type="button" class="dz-btn" id="dzJobStop" onclick="_dzCancelJob()" ${_dzStopAsked() ? 'disabled' : ''} title="Delete nothing more after the delete in flight; what was deleted is activated">${_dzStopAsked() ? 'Stopping…' : 'Stop'}</button><button class="dz-btn danger" disabled>Removing…</button></div>`;
}

function _dzRemovalDone() {
  const R = DZ.removal, body = document.getElementById('dzBody'), data = R.result || {};
  const s = data.summary || {};
  const kept = data.kept || [];
  const line = (label, n, cls) => n ? `<div class="dz-row ${cls}"><span class="ic">•</span><div><div class="nm">${n} ${label}</div></div></div>` : '';
  const v = data.verification || {};
  const remaining = v.remaining || [];
  const verifyCard = !v.read
    ? `<div class="dz-card sev-medium"><div class="bar"></div><div><div class="t">Not verified</div><div class="d">The tenant could not be re-read after the removal${(v.blockers || []).length ? `: ${_dzE(v.blockers.join('; '))}` : ''}. Click <strong>Verify again</strong> once the API is reachable.</div></div></div>`
    : (v.clean
      ? `<div class="dz-card sev-info"><div class="bar"></div><div><div class="t">Verified: nothing of ${_dzE(R.pack.name || R.id)} remains in the tenant</div><div class="d">A fresh read after activation${v.activation_status ? ` (ZIA status ${_dzE(v.activation_status)})` : ''} found no rule, engine, application group or dictionary of this pack on any channel.${(v.kept || []).length ? ` ${v.kept.length} object(s) were kept on purpose because something else still uses them.` : ''}</div></div></div>`
      : `<div class="dz-card sev-high"><div class="bar"></div><div><div class="t">Verification found ${remaining.length} object(s) still in the tenant</div><div class="d">A fresh read after activation${v.activation_status ? ` (ZIA status ${_dzE(v.activation_status)})` : ''} still lists these. Activate in ZIA if the status is not ACTIVE, then click <strong>Remove leftovers</strong> to run the removal again on exactly these objects.</div></div></div>
         <div class="dz-rows">${remaining.map(i => `<div class="dz-row st-fail"><span class="ic">!</span><div><div class="nm">${_dzE(RM_KIND[i.kind] || i.kind)}: ${_dzE(i.name)}${i.channel ? ` <span class="dz-chip kind-channel">${_dzE(_dzChan(i.channel))}</span>` : ''}</div></div></div>`).join('')}</div>`);
  body.innerHTML = `
    ${data.stopped ? `<div class="dz-card sev-high"><div class="bar"></div><div><div class="t">The removal stopped early</div><div class="d">${_dzE(data.stopped)} What was already deleted is activated; the objects listed as left alone were never sent. Run the removal again once this is fixed.</div></div></div>` : ''}
    ${verifyCard}
    <div class="dz-card ${data.status === 'removed' ? 'sev-info' : 'sev-medium'}"><div class="bar"></div><div>
      <div class="t">Removal ${_dzE(data.status || '')}</div>
      <div class="d">${data.activation && data.activation.activated ? 'Activated in ZIA automatically — the deletions are live.' : (data.activation_required ? `Automatic activation did not run${data.activation && data.activation.error ? ` (${_dzE(data.activation.error)})` : ''}; activate in ZIA to make the deletions live.` : 'Nothing needed activation.')}</div></div></div>
    <div class="dz-rows">
      ${line('deleted', s.deleted, 'st-ok')}${line('already gone', s.gone, 'st-reuse')}${line('left alone', s.skipped, 'st-differs')}${line('failed', s.failed, 'st-fail')}${line('still present', s.still_present, 'st-fail')}
    </div>
    ${(data.results || []).filter(x => x.status === 'failed' || x.status === 'skipped' || x.status === 'still_present').length ? `<div class="dz-h" style="margin-top:0.8rem;">Not removed</div><div class="dz-rows">${(data.results || []).filter(x => x.status === 'failed' || x.status === 'skipped' || x.status === 'still_present').map(x => `<div class="dz-row st-fail"><span class="ic">!</span><div><div class="nm">${_dzE(x.name)}</div><div class="rs">${_dzE(x.error ? (x.explanation ? `${x.error} — What this means: ${x.explanation}` : x.error) : (x.reason || ''))}</div></div></div>`).join('')}</div>` : ''}
    ${kept.length ? `<div class="dz-h" style="margin-top:0.8rem;">Kept (still in use)<span class="count">${kept.length}</span></div><div class="dz-rows">${kept.map(i => `<div class="dz-row st-reuse"><span class="ic">↺</span><div><div class="nm">${_dzE(RM_KIND[i.kind] || i.kind)}: ${_dzE(i.name)}</div><div class="rs">${_dzE(i.keep || '')}</div></div></div>`).join('')}</div>` : ''}
    ${(data.logs || []).length ? `<details class="dz-fold"><summary><div class="dz-h">Log</div></summary><div class="dz-log">${_dzE(data.logs.join('\n'))}</div></details>` : ''}`;
  document.getElementById('dzFoot').innerHTML = `
    <div class="dz-summary">Removal ${_dzE(data.status || 'finished')}${v.read ? (v.clean ? ' · verified by a fresh read.' : ` · ${_dzN(remaining.length, 'object')} still present.`) : ' · not verified yet.'}</div>
    <div class="dz-actions">
      <button type="button" class="dz-btn quiet" onclick="_dzRemovalVerifyAgain()" ${DZ.busy ? 'disabled' : ''}>Verify again</button>
      ${remaining.length && v.plan ? `<button type="button" class="dz-btn danger" onclick="_dzRemovalLeftovers()">Remove leftovers</button>` : ''}
      <button type="button" class="dz-btn primary" onclick="_dzRemovalClose()">Back to packs</button>
    </div>`;
}

// A fresh read of the tenant, on demand: the same discovery the preview
// runs, so "nothing remains" is proven the same way it was planned.
async function _dzRemovalVerifyAgain() {
  const R = DZ.removal; if (!R || DZ.busy) return;
  DZ.busy = true; announce('Re-reading the tenant…');
  try {
    const r = await fetch('/api/dlp-packs/removal/preflight', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ..._dzRemovalScope(), ..._dzCreds() }) });
    const plan = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((plan.detail && (plan.detail.cause || plan.detail)) || `HTTP ${r.status}`);
    const remaining = (plan.items || []).filter(i => i.status === 'remove');
    R.result = R.result || { status: 'nothing', summary: {}, results: [] };
    R.result.verification = { read: plan.status !== 'blocked', clean: plan.status !== 'blocked' && !remaining.length, remaining, kept: (plan.items || []).filter(i => i.status === 'keep'), plan, blockers: plan.blockers || [] };
    announce(remaining.length ? `${remaining.length} object(s) still present.` : 'Verified: nothing remains.');
  } catch (e) {
    R.result = R.result || { status: 'nothing', summary: {}, results: [] };
    R.result.verification = { read: false, clean: false, remaining: [], blockers: [e.message] };
  } finally { DZ.busy = false; _dzRemovalRender(); }
}

// Run the wizard again on exactly what the verification read found.
function _dzRemovalLeftovers() {
  const R = DZ.removal; if (!R || !R.result || !R.result.verification || !R.result.verification.plan) return;
  const plan = R.result.verification.plan;
  plan.tenant_label = plan.tenant_label || R.plan.tenant_label;
  DZ.removal = { id: R.id, ids: R.ids, mode: R.mode, rules: R.rules, inventory: R.inventory, selected: R.selected, pack: R.pack, plan, step: 2, result: null, consent: false };
  _dzRemovalRender();
}

async function _dzRemovalApply() {
  const R = DZ.removal; if (!R) return;
  if (window.dlpReadiness && !window.dlpReadiness.allowWrite('remove_packs')) return;
  const remove = (R.plan.items || []).filter(i => i.status === 'remove');
  // Second confirmation (the consent checkbox was the first): a final,
  // explicit yes naming the rules and the tenant before anything is deleted.
  const rules = remove.filter(i => i.kind === 'policy').map(i => i.name);
  const others = remove.length - rules.length;
  const named = rules.slice(0, 8).map(n => `  • ${n}`).join('\n') + (rules.length > 8 ? `\n  … and ${rules.length - 8} more` : '');
  // The typed phrase names how many objects go; the server checks it
  // against the plan it re-makes from a fresh read before deleting anything.
  const phrase = R.plan.confirm_phrase || `DELETE ${remove.length} OBJECTS`;
  const body = `Permanently remove ${rules.length} rule(s) from ${R.plan.tenant_label || 'this tenant'}:\n${named || '  (none)'}\n\nplus ${others} engine(s) and dictionar${others === 1 ? 'y' : 'ies'} that nothing else uses (checked again right before each one goes).\n\n${R.plan.rate_forecast ? _dzRateText(R.plan.rate_forecast) + '\n\n' : ''}This cannot be undone from here.`;
  let typed = '';
  const dlg = _dzDlg();
  if (dlg && dlg.phrase) typed = await dlg.phrase({ title: 'Final confirmation', body, phrase, okLabel: 'Remove now' });
  else { try { typed = window.prompt(`Final confirmation.\n\n${body}\n\nType ${phrase} to remove:`, ''); } catch (e) { typed = null; } }
  if (!typed) return;
  DZ.busy = true; R.step = 3; DZ.job = null; _dzRemovalRender();
  try {
    const snap = await _dzRunJob('/api/dlp-packs/removal/apply/start', { ..._dzRemovalScope(), plan_hash: R.plan.plan_hash, confirm: true, confirm_phrase: String(typed).trim(), ..._dzCreds() });
    if (snap.status === 'failed' || !snap.result) throw new Error(snap.error || 'The run ended without a result.');
    const data = snap.result;
    if (data.status === 'blocked' || data.status === 'stale') throw new Error(data.message || (data.blockers || []).join('; ') || `Removal ${data.status}.`);
    if (!data.logs || !data.logs.length) data.logs = snap.logs;
    R.result = data;
    announce(`Removal ${data.status}.`);
  } catch (e) {
    R.result = { status: 'failed', summary: {}, results: [{ status: 'failed', name: R.pack.name || R.id, error: e.message }], logs: (DZ.job || {}).logs || [] };
  } finally {
    R.step = 4; DZ.busy = false; _dzRemovalRender();
  }
}

// Printable removal report — opens a clean page the operator can save as
// PDF (browser Print). Explanations and details in a table; no live tenant
// calls, just the plan already previewed.
function _dzRemovalReport() {
  const R = DZ.removal; if (!R) return;
  const items = R.plan.items || [];
  const esc = s => String(s == null ? '' : s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
  const rows = items.slice().sort((a, b) => (a.status === b.status ? 0 : a.status === 'remove' ? -1 : 1)).map(i => `
    <tr class="${i.status}">
      <td>${esc(RM_KIND[i.kind] || i.kind)}</td><td>${esc(i.name)}</td><td>${esc(i.channel || '')}</td>
      <td><b>${i.status === 'remove' ? 'Remove' : 'Keep'}</b></td>
      <td>${i.status === 'keep' ? esc(i.keep) : (i.match === 'name' ? 'Matched by name only (no Zscaler Made Easy tag) — confirm ownership' : 'Carries this pack’s Zscaler Made Easy provenance tag')}</td>
    </tr>`).join('');
  const remove = items.filter(i => i.status === 'remove').length, keep = items.length - remove;
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Removal plan — ${esc(R.pack.name || R.id)}</title>
    <style>
      body{font-family:-apple-system,Segoe UI,Arial,sans-serif;color:#14202b;margin:2rem;line-height:1.5}
      h1{font-size:1.4rem;margin:0 0 .2rem} .sub{color:#5f6b76;margin:0 0 1rem}
      .stat{display:flex;gap:1.5rem;margin:1rem 0;font-size:.9rem}
      table{border-collapse:collapse;width:100%;font-size:.82rem;margin-top:1rem}
      th,td{border:1px solid #d9dfe3;padding:.4rem .55rem;text-align:left;vertical-align:top}
      th{background:#eef1f3;text-transform:uppercase;font-size:.68rem;letter-spacing:.05em}
      tr.remove td:nth-child(4){color:#b91c1c} tr.keep td:nth-child(4){color:#5f6b76}
      .method{color:#5f6b76;font-size:.8rem;margin-top:1.2rem}
      @media print{.noprint{display:none}}
      .btn{margin:0 .4rem 1rem 0;padding:.5rem .9rem;border:1px solid #2563eb;background:#2563eb;color:#fff;border-radius:6px;cursor:pointer;font-size:.85rem}
    </style></head><body>
    <div class="noprint"><button class="btn" onclick="window.print()">Print or save as PDF</button></div>
    <h1>Removal plan — ${esc(R.pack.name || R.id)}</h1>
    <p class="sub">Tenant ${esc(R.plan.tenant_label || '')} · generated ${new Date().toLocaleString()}</p>
    <div class="stat"><div><b>${remove}</b> to remove</div><div><b>${keep}</b> kept (still in use)</div></div>
    <p>This is the plan previewed in Zscaler Made Easy. Removal deletes objects in dependency order — rules, then endpoint application groups, then engines, then dictionaries — so nothing is deleted while something still points at it. An engine a surviving rule still uses, and a dictionary a surviving engine still uses, are kept and listed below. Predefined Zscaler dictionaries are never removed. Zscaler Made Easy activates the changes in ZIA automatically as the removal runs, so the deletions are live when it finishes.</p>
    <table><thead><tr><th>Type</th><th>Name</th><th>Channel</th><th>Decision</th><th>Why</th></tr></thead><tbody>${rows}</tbody></table>
    <p class="method">Objects are matched to the pack by the Zscaler Made Easy provenance tag written into each object’s description at deploy time, and by the names the pack defines. Name-only matches carry no tag and are flagged for confirmation.</p>
    </body></html>`;
  const w = window.open('', '_blank');
  if (!w) { alert('Allow pop-ups to open the printable report.'); return; }
  w.document.write(html); w.document.close();
}

// ── Previous deployments and undo ─────────────────────────────────
// Every deploy made from here is recorded (what was created, where).
// Undo deletes exactly those objects, newest first in dependency order,
// and leaves alone anything the customer renamed or that is still in use.
async function _dzLoadDeployments() {
  try {
    const r = await fetch('/api/deployments', { cache: 'no-store' });
    DZ.deployments = r.ok ? ((await r.json()).deployments || []) : [];
  } catch (e) { DZ.deployments = []; }
  if (DZ.step === 1) _dzRenderSelect();
}
function _dzDeploymentsHtml() {
  const rows = DZ.deployments;
  if (rows === null) return '';
  const writeOn = !!(DZ.write && DZ.write.enabled);
  const fmt = iso => { try { return new Date(iso).toLocaleString(); } catch (e) { return iso || ''; } };
  const kinds = k => Object.entries(k || {}).map(([kind, n]) => _dzN(n, ...(DZ_KIND_PLURAL[kind] || [kind]))).join(', ');
  // A deployment record is stored data: an unknown channel name is shown escaped, never as markup.
  const chans = ct => Object.entries(ct || {}).map(([pid, chs]) => `${_dzE(pid)}: ${_dzE((Array.isArray(chs) ? chs : []).map(c => DZ_DLP_LABEL[c] || c).join(', ') || 'as packed')}`).join(' · ');
  const list = rows.slice(0, 12).map(d => {
    const done = d.remaining === 0 && d.created > 0;
    const busy = DZ.undoBusy === d.id;
    const res = DZ.undoResult && DZ.undoResult.id === d.id ? DZ.undoResult : null;
    return `<div class="dz-row ${done ? 'st-reuse' : 'st-ok'}">
      <span class="ic" aria-hidden="true">${done ? '↺' : '✓'}</span>
      <div><div class="nm">${_dzE(fmt(d.at))} · ${_dzE(d.tenant_label || '')} · ${_dzE((d.packs || []).join(', '))}${d.by ? ` · by ${_dzE(d.by)}` : ''}</div>
        <div class="rs">${_dzE(kinds(d.created_by_kind))} created${d.remaining !== d.created ? ` · ${d.created - d.remaining} already undone` : ''}${d.channel_targets && Object.keys(d.channel_targets).length ? ` · ${chans(d.channel_targets)}` : ''}${done ? ` · undone ${_dzE(fmt(d.undone_at))}` : ''}</div>
        ${res ? `<div class="rs">${_dzE(res.text)}</div>` : ''}</div>
      <div class="tags">${done ? '<span class="dz-chip">Undone</span>' : `<button type="button" class="dz-btn quiet dz-btn-sm" ${busy || !writeOn ? 'disabled' : ''} title="${writeOn ? 'Delete what this deployment created' : 'Enable write mode to undo'}" onclick="event.stopPropagation(); _dzUndo('${_dzE(d.id)}')">${busy ? 'Undoing…' : `Undo (${d.remaining})`}</button>`}</div>
    </div>`;
  }).join('');
  return `<div class="dz-h" style="margin-top:1rem;">Previous deployments from this app<span class="count">${rows.length}</span></div>
    ${rows.length ? `<div class="dz-rows">${list}</div><div class="dz-flow-hint">Undo deletes only the objects a deployment created here, in order (rules, application groups, engines, dictionaries). Objects the customer renamed or that another rule still uses are left alone and listed. Deletions need activation in ZIA like any change.${writeOn ? '' : ' Enable write mode to undo.'}</div>`
              : `<div class="dz-flow-hint">Nothing deployed from this app yet. Every deploy is recorded here so it can be undone.</div>`}`;
}
async function _dzUndo(id) {
  const d = (DZ.deployments || []).find(x => x.id === id);
  if (!d) return;
  // The undo of a deployment is a removal like any other: it goes
  // through Preview → Approve → Remove → Verify with a plan hash, the
  // consent step, tiered deletes with activation and a read-back.
  DZ.undoResult = null;
  await _dzRemove({ deployment: d });
}
async function _dzUndoLast() {
  const id = DZ.result && DZ.result.deployment_id;
  if (!id) return;
  await _dzLoadDeployments();
  DZ.step = 1; DZ.report = null; DZ.result = null; _dzRender();
  _dzUndo(id);
}
// After a deployment undo finishes in the wizard, the history reflects it.
const _dzRemovalRenderBase = _dzRemovalRender;
_dzRemovalRender = function () {
  const R = DZ.removal;
  if (R && R.mode === 'deployment' && R.result && !R._reloaded) { R._reloaded = true; _dzLoadDeployments().then(() => { if (DZ.removal === R) _dzRemovalRenderBase(); }); }
  return _dzRemovalRenderBase();
};

// ── Flow diagram ────────────────────────────────────────────────
// Visualises how the selected packs wire into the tenant:
//   tenant templates → dictionaries → engines → policies
// Nodes are coloured by plan status (and by deploy result once a run
// has finished). Hover traces everything upstream and downstream of a
// node; click pins the trace; edges into objects that will be created
// carry a slow animated flow (disabled under prefers-reduced-motion).
const DZ_FLOW = { pinned: null, scale: 1, W: 0, H: 0 };
const DZ_FLOW_COLS = [
  { key: 'template',   title: 'Tenant templates' },
  { key: 'dictionary', title: 'Dictionaries' },
  { key: 'engine',     title: 'Engines' },
  { key: 'app_group',  title: 'App groups' },
  { key: 'policy',     title: 'Policies' },
  { key: 'resource',   title: 'Applies to / requires' },
];
const DZ_FLOW_GEO = { w: 224, h: 60, gapY: 14, gapX: 96, pad: 22, head: 34 };

function _dzFlowGraph(items, results) {
  const nodes = new Map();
  const edges = [];
  const resultBy = {};
  (results || []).forEach(r => { resultBy[`${r.kind}:${r.name}`] = r; });
  const col = k => Math.max(0, DZ_FLOW_COLS.findIndex(c => c.key === k));
  const add = (kind, name, status, extra) => {
    const key = `${kind}:${name}`;
    if (!nodes.has(key)) nodes.set(key, { key, kind, name, status, col: col(kind), in: [], out: [], ...(extra || {}) });
    return nodes.get(key);
  };
  for (const it of items) {
    if (it.kind === 'tweak') {
      const tname = (it.tenant && it.tenant.name) || it.name;
      const n = add('dictionary', tname, 'tenant', { reason: it.reason, packs: it.packs });
      if (it.status === 'modify') { n.status = 'modify'; n.reason = it.reason; n.tweak = true; }
      continue;
    }
    add(it.kind, it.name, it.status, { reason: it.reason, packs: it.packs, warnings: it.warnings, tenant: it.tenant,
                                       channel: it.detail && it.detail.channel });
  }
  for (const it of items) {
    if (it.kind === 'tweak') continue;
    for (const dep of (it.depends_on || [])) {
      const i = dep.indexOf(':');
      const dk = dep.slice(0, i), dn = dep.slice(i + 1);
      const kind = dk === 'predefined' ? 'template' : (dk === 'missing' ? 'resource' : dk);
      const from = add(kind, dn, dk === 'missing' ? 'missing' : 'tenant', {
        reason: kind === 'template' ? 'Predefined Zscaler dictionary used as a clone template.'
              : kind === 'resource' ? (dk === 'missing' ? 'Not present in the tenant — the rules that need it are skipped.' : 'Tenant prerequisite, resolved by name.')
              : 'Already present in the tenant.',
        packs: [],
      });
      if (dk === 'missing') from.status = 'missing';
      const to = nodes.get(`${it.kind}:${it.name}`);
      if (kind === 'resource') {
        // Tenant prerequisites sit to the RIGHT of policies: the policy
        // "applies to" a SaaS tenant / "requires" a template or label.
        edges.push({ from: to.key, to: from.key });
        to.out.push(from.key); from.in.push(to.key);
        continue;
      }
      edges.push({ from: from.key, to: to.key });
      from.out.push(to.key); to.in.push(from.key);
    }
  }
  for (const n of nodes.values()) {
    const r = resultBy[n.key];
    if (r) { n.result = r.status; n.resultText = (r.error ? (r.explanation ? `${r.error} — What this means: ${r.explanation}` : r.error) : '') || r.reason || (r.id ? `ID ${r.id}` : ''); }
  }
  // Column ordering: sources alphabetical, downstream by barycenter of inputs.
  const cols = DZ_FLOW_COLS.map(() => []);
  for (const n of nodes.values()) cols[n.col].push(n);
  const idx = {};
  for (let c = 0; c < cols.length; c++) {
    const bary = n => { const v = n.in.map(k => idx[k]).filter(x => x != null); return v.length ? v.reduce((a, b) => a + b, 0) / v.length : 1e9; };
    cols[c].sort((a, b) => (c < 2 ? 0 : bary(a) - bary(b)) || a.name.localeCompare(b.name));
    cols[c].forEach((n, i) => { idx[n.key] = i; n.row = i; });
  }
  const used = cols.map((c, i) => ({ c, i })).filter(x => x.c.length);
  used.forEach((u, ci) => u.c.forEach(n => { n.cx = ci; }));
  const G = DZ_FLOW_GEO;
  for (const n of nodes.values()) {
    n.x = G.pad + n.cx * (G.w + G.gapX);
    n.y = G.pad + G.head + n.row * (G.h + G.gapY);
  }
  const rows = Math.max(1, ...used.map(u => u.c.length));
  DZ_FLOW.W = G.pad * 2 + used.length * G.w + Math.max(0, used.length - 1) * G.gapX;
  DZ_FLOW.H = G.pad * 2 + G.head + rows * (G.h + G.gapY) - G.gapY;
  return { nodes, edges, used };
}

const DZ_FLOW_STATUS = {
  create: 'st-create', modify: 'st-modify', restore: 'st-modify', reuse: 'st-reuse', reuse_differs: 'st-differs',
  conflict: 'st-blocked', blocked_dependency: 'st-blocked', skip_empty: 'st-blocked', noop: 'st-reuse', tenant: 'st-tenant',
  missing: 'st-fail',
  created: 'st-ok', modified: 'st-ok', restored: 'st-ok', reused: 'st-reuse', skipped: 'st-blocked', failed: 'st-fail',
  remove: 'st-fail', keep: 'st-reuse', deleted: 'st-ok', gone: 'st-reuse', still_present: 'st-fail',
};
const DZ_FLOW_LABEL = {
  create: 'will create', modify: 'will modify', restore: 'will overwrite', reuse: 'already present', reuse_differs: 'kept as-is (differs)',
  conflict: 'conflict', blocked_dependency: 'skipped', skip_empty: 'skipped', noop: 'no change', tenant: 'in tenant',
  missing: 'MISSING',
  created: 'created', modified: 'modified', restored: 'overwritten', reused: 'reused', skipped: 'skipped', failed: 'FAILED',
  remove: 'will remove', keep: 'kept (in use)', deleted: 'removed', gone: 'already gone', still_present: 'STILL PRESENT',
};

// opts.standalone: drawn in its own tab (/report/flow) — no "open in new
// tab" button and no hint, the page has its own.
function _dzFlowHtml(items, results, opts) {
  if (!items || !items.length) return `<div class="dz-empty">Nothing to draw.</div>`;
  const standalone = !!(opts && opts.standalone);
  const g = _dzFlowGraph(items, results);
  DZ_FLOW.graph = g;
  const G = DZ_FLOW_GEO;
  const trunc = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
  const heads = g.used.map((u, ci) => `<text class="dz-flow-head" x="${G.pad + ci * (G.w + G.gapX)}" y="${G.pad + 14}">${_dzE(DZ_FLOW_COLS[u.i].title.toUpperCase())}</text>`).join('');
  const edgeHtml = g.edges.map(e => {
    const a = g.nodes.get(e.from), b = g.nodes.get(e.to);
    const x1 = a.x + G.w, y1 = a.y + G.h / 2, x2 = b.x, y2 = b.y + G.h / 2, dx = G.gapX * 0.55;
    const st = b.result || b.status;
    const flow = (st === 'create' || st === 'modify' || st === 'restore' || st === 'created' || st === 'modified' || st === 'restored') ? ' flow' : '';
    const bad = (st === 'conflict' || st === 'blocked_dependency' || st === 'skip_empty' || st === 'skipped' || st === 'failed' || st === 'remove' || st === 'deleted') ? ' bad' : '';
    return `<path class="dz-edge${flow}${bad}" data-from="${_dzE(e.from)}" data-to="${_dzE(e.to)}" d="M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}"/>`;
  }).join('');
  const nodeHtml = [...g.nodes.values()].map(n => {
    const st = n.result || n.status;
    const cls = DZ_FLOW_STATUS[st] || 'st-reuse';
    const label = DZ_FLOW_LABEL[st] || st;
    const tip = `${DZ_KIND[n.kind] || n.kind}: ${n.name}\n${label}${n.reason ? '\n' + n.reason : ''}${n.resultText ? '\n' + n.resultText : ''}`;
    return `<g class="dz-node ${cls}" data-key="${_dzE(n.key)}" transform="translate(${n.x},${n.y})" tabindex="0" role="img" aria-label="${_dzE(tip)}">
      <title>${_dzE(tip)}</title>
      <rect class="box" width="${G.w}" height="${G.h}" rx="12"/>
      <rect class="bar" width="4" height="${G.h - 12}" x="6" y="6" rx="2"/>
      <text class="kind" x="18" y="16">${_dzE((DZ_KIND[n.kind] || n.kind).toUpperCase())}${n.channel ? ' · ' + _dzE(_dzChan(n.channel).toUpperCase()) : ''}${n.tweak ? ' · TWEAK' : ''}</text>
      <text class="st" x="${G.w - 10}" y="16" text-anchor="end">${_dzE(label)}</text>
      <text class="name" x="18" y="34">${_dzE(trunc(n.name, 27))}</text>
      <text class="pk" x="18" y="50">${_dzE(trunc(n.packs && n.packs.length ? n.packs.join(', ') : (n.kind === 'template' ? 'Zscaler predefined' : 'existing in tenant'), 36))}</text>
    </g>`;
  }).join('');
  const counts = { create: 0, modify: 0, reuse: 0, blocked: 0, tenant: 0 };
  for (const n of g.nodes.values()) {
    const st = n.result || n.status;
    if (st === 'create' || st === 'created') counts.create++;
    else if (st === 'modify' || st === 'modified' || st === 'restore' || st === 'restored') counts.modify++;
    else if (st === 'tenant') counts.tenant++;
    else if (['conflict', 'blocked_dependency', 'skip_empty', 'skipped', 'failed', 'missing'].includes(st)) counts.blocked++;
    else counts.reuse++;
  }
  return `
    <div class="dz-flow">
      <div class="dz-flow-bar">
        <div class="dz-flow-legend">
          <span><i class="sw st-create"></i>${results ? 'created' : 'will create'} ${counts.create}</span>
          <span><i class="sw st-modify"></i>${results ? 'modified' : 'modify'} ${counts.modify}</span>
          <span><i class="sw st-reuse"></i>reuse ${counts.reuse}</span>
          <span><i class="sw st-tenant"></i>tenant ${counts.tenant}</span>
          <span><i class="sw st-blocked"></i>skipped/blocked ${counts.blocked}</span>
        </div>
        <div class="dz-flow-zoom" role="group" aria-label="Zoom">
          <button type="button" class="dz-btn quiet" onclick="_dzFlowZoom(-0.15)" aria-label="Zoom out">−</button>
          <button type="button" class="dz-btn quiet" onclick="_dzFlowZoom(0)" aria-label="Fit to width">Fit</button>
          <button type="button" class="dz-btn quiet" onclick="_dzFlowZoom(0.15)" aria-label="Zoom in">+</button>
          ${standalone ? '' : `<button type="button" class="dz-btn quiet dz-flow-open" onclick="_dzFlowOpenTab()" title="Open this flow in its own tab, full width, with a details panel. It stays live while this window is open.">↗ Open in new tab</button>`}
        </div>
      </div>
      <div class="dz-flow-wrap" id="dzFlowWrap" onmouseover="_dzFlowOver(event)" onmouseout="_dzFlowOut(event)" onclick="_dzFlowClick(event)" onkeydown="_dzFlowKey(event)">
        <svg id="dzFlowSvg" viewBox="0 0 ${DZ_FLOW.W} ${DZ_FLOW.H}" width="${DZ_FLOW.W}" height="${DZ_FLOW.H}" role="group" aria-label="Dependency flow: templates to dictionaries to engines to policies">
          <g class="dz-heads">${heads}</g>
          <g class="dz-edges">${edgeHtml}</g>
          <g class="dz-nodes">${nodeHtml}</g>
        </svg>
      </div>
      ${standalone ? '' : `<div class="dz-flow-hint">Hover a node to trace what it depends on and what depends on it. Click to pin. Names are truncated — hover for the full name and reason, or open the flow in its own tab for the full-width view with a details panel.</div>`}
    </div>`;
}

// ── The flow in its own tab (/report/flow) ──────────────────────────
// The tab draws the same diagram itself (deploy_studio.js is loaded there
// too), so hover, pin, keyboard and zoom all work natively; this window
// just hands it the plan and keeps it current. The last plan is also kept
// in localStorage so the tab survives a reload after this window is gone.
const DZ_FLOW_LS = 'zassess_flow_last';
function _dzFlowPayload(items, results) {
  const R = DZ.report || {}, X = DZ.result || {};
  return {
    items: items || [], results: results || null, stage: results ? 'deployed' : 'plan',
    tenant_label: R.tenant_label || '', packs: [...(DZ.selected || [])],
    plan_hash: (results ? X.plan_hash : R.plan_hash) || '', status: results ? (X.status || '') : (R.status || ''),
    at: new Date().toISOString(),
  };
}
// Remember the plan currently drawn and push it to the flow tab if one is open.
function _dzFlowSyncTab(items, results) {
  const payload = _dzFlowPayload(items, results);
  DZ_FLOW.last = payload;
  try { localStorage.setItem(DZ_FLOW_LS, JSON.stringify(payload)); } catch (e) { /* storage unavailable or full */ }
  const win = DZ_FLOW.win;
  if (!win || win.closed) { DZ_FLOW.win = null; return; }
  try { if (typeof win.__flowApply === 'function') win.__flowApply(payload); } catch (e) { /* the tab is still loading; it reads the plan itself */ }
}
function _dzFlowOpenTab() {
  if (!DZ_FLOW.last) return;
  const win = window.open('/report/flow', '_blank');
  if (!win) return;   // popup blocked: the inline flow is still there
  DZ_FLOW.win = win;
  let tries = 0;
  const push = setInterval(() => {
    if (win.closed || tries++ > 100) { clearInterval(push); return; }
    try {
      if (typeof win.__flowApply !== 'function') return;
      win.__flowApply(DZ_FLOW.last); clearInterval(push);
    } catch (e) { /* not ready yet */ }
  }, 120);
}
// Lets the tab ask for the latest plan (after a reload, for example).
window.__flowCurrent = () => DZ_FLOW.last || null;

function _dzViewToggle() {
  const v = DZ.view || 'flow';
  return `<div class="dz-seg" role="tablist" aria-label="View">
    <button type="button" role="tab" aria-selected="${v === 'flow'}" class="${v === 'flow' ? 'on' : ''}" onclick="DZ.view='flow';_dzRender()">Flow</button>
    <button type="button" role="tab" aria-selected="${v === 'list'}" class="${v === 'list' ? 'on' : ''}" onclick="DZ.view='list';_dzRender()">List</button>
  </div>`;
}

function _dzFlowZoom(delta) {
  const svg = document.getElementById('dzFlowSvg'), wrap = document.getElementById('dzFlowWrap');
  if (!svg || !wrap) return;
  if (delta === 0) DZ_FLOW.scale = Math.max(0.35, Math.min(1, (wrap.clientWidth - 16) / DZ_FLOW.W));
  else DZ_FLOW.scale = Math.max(0.35, Math.min(2, DZ_FLOW.scale + delta));
  svg.setAttribute('width', Math.round(DZ_FLOW.W * DZ_FLOW.scale));
  svg.setAttribute('height', Math.round(DZ_FLOW.H * DZ_FLOW.scale));
}

function _dzFlowRelated(key) {
  const svg = document.getElementById('dzFlowSvg');
  const edges = [...svg.querySelectorAll('.dz-edge')].map(p => ({ from: p.dataset.from, to: p.dataset.to, el: p }));
  const keep = new Set([key]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const e of edges) {
      if (keep.has(e.to) && !keep.has(e.from)) { keep.add(e.from); grew = true; }
      if (keep.has(e.from) && !keep.has(e.to)) { keep.add(e.to); grew = true; }
    }
  }
  return { keep, edges };
}
function _dzFlowTrace(key) {
  const svg = document.getElementById('dzFlowSvg');
  if (!svg) return;
  const notify = () => { if (typeof DZ_FLOW.onTrace === 'function') DZ_FLOW.onTrace(key, key && DZ_FLOW.graph ? DZ_FLOW.graph.nodes.get(key) : null); };
  if (!key) {
    svg.querySelectorAll('.is-dim, .is-hi').forEach(el => el.classList.remove('is-dim', 'is-hi'));
    notify();
    return;
  }
  const { keep, edges } = _dzFlowRelated(key);
  svg.querySelectorAll('.dz-node').forEach(n => n.classList.toggle('is-dim', !keep.has(n.dataset.key)));
  for (const e of edges) {
    const on = keep.has(e.from) && keep.has(e.to);
    e.el.classList.toggle('is-hi', on); e.el.classList.toggle('is-dim', !on);
  }
  notify();
}
function _dzFlowOver(ev) { const n = ev.target.closest('.dz-node'); if (n && !DZ_FLOW.pinned) _dzFlowTrace(n.dataset.key); }
function _dzFlowOut(ev) { if (!DZ_FLOW.pinned && ev.target.closest('.dz-node')) _dzFlowTrace(null); }
function _dzFlowClick(ev) {
  const n = ev.target.closest('.dz-node');
  const key = n ? n.dataset.key : null;
  DZ_FLOW.pinned = (key && DZ_FLOW.pinned !== key) ? key : null;
  _dzFlowTrace(DZ_FLOW.pinned);
}
function _dzFlowKey(ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); _dzFlowClick(ev); } if (ev.key === 'Escape') { DZ_FLOW.pinned = null; _dzFlowTrace(null); } }

// Loaded by the server after index.html's inline script, so the definitions
// above replace the legacy pack-import modal. Relabel its launcher button.
(function () {
  const btn = document.querySelector('button[onclick="openDlpPacksModal()"]');
  if (!btn) return;
  btn.innerHTML = '<span aria-hidden="true">\u{1F4E6}</span> Deploy policy packs';
  btn.setAttribute('aria-label', 'Deploy DLP policy packs with dependency checks, impact review, and approval');
})();


// ── Export from tenant as a pack ────────────────────────────────────
// The rules the operator ticks (every DLP rule to start with) with every
// engine they use and every dictionary those engines use, as a zip in the
// policy pack layout. The tenant is only read: the rule list comes from
// the same inventory the removal picker uses, the export runs as a
// background job the page follows, and the zip comes from the finished job.
async function _dzExportPick() {
  DZ.exportBusy = true; _dzRenderSelect();
  let inv;
  try {
    const r = await fetch('/api/dlp-packs/removal/inventory', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ..._dzCreds(), ..._dzScope() }) });
    inv = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((inv.detail && (inv.detail.cause || inv.detail)) || `HTTP ${r.status}`);
  } catch (e) {
    DZ.exportBusy = false; _dzRenderSelect();
    alert(`Could not list the tenant's DLP rules: ${e.message}`);
    return;
  }
  DZ.exportBusy = false;
  if (inv.status === 'blocked') { alert((inv.blockers || ['Could not read the tenant.']).join('\n')); _dzRenderSelect(); return; }
  // Endpoint sub-rules travel with their parent rule, so only top-level rules are listed.
  const rules = (inv.rules || []).filter(r => r.parent_id == null);
  // Custom dictionaries (clones included) and custom engines, each pickable on its own.
  const dicts = Object.entries(inv.dictionaries || {}).filter(([, d]) => d && d.custom && d.id != null)
    .map(([name, d]) => ({ id: String(d.id), name, type: d.type || '' })).sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
  const engines = (inv.engines || []).filter(e => e.id != null).map(e => Object.assign({}, e, { id: String(e.id) }));
  DZ.exportPack = { inventory: inv, rules, selected: new Set(rules.map(r => `${r.channel}:${r.id}`)), filter: '', name: '', result: null, running: false,
    dicts, engines, selDicts: new Set(dicts.map(d => d.id)), selEngines: new Set(engines.map(e => e.id)),
    parts: new Set(['rules']), deps: true, format: 'json' };
  _dzExportRender();
}
// What an export carries and how (defaults: rules, with what they use, as a JSON pack).
// An engine's expression with dictionary names and one plain sentence
// (engine_explain, through the inventory); Copy puts the expression as the
// tenant has it (dictionary ids) on the clipboard.
function _dzEngineExplain(o) {
  if (!o || !(o.readable || o.expression)) return '';
  return `${o.summary ? `<div class="rs dz-expl">${_dzE(o.summary)}</div>` : ''}<div class="rs"><code class="dz-expr" title="${_dzE(o.expression || '')}">${_dzE(o.readable || o.expression)}</code>
    <button type="button" class="dz-link" data-expr="${_dzE(o.expression || '')}" aria-label="Copy the expression of ${_dzE(o.name || 'this engine')} with dictionary ids" onclick="event.preventDefault();_dzCopyExpr(this)">Copy expression</button></div>`;
}
function _dzCopyExpr(btn) {
  const raw = btn.dataset.expr || '';
  const done = t => { btn.textContent = t; setTimeout(() => { btn.textContent = 'Copy expression'; }, 2000); };
  try { navigator.clipboard.writeText(raw).then(() => done('Copied'), () => done('Copy blocked')); } catch (e) { done('Copy blocked'); }
}
function _dzExportParts(X) { return X.parts instanceof Set ? X.parts : new Set(['rules']); }
function _dzExportPart(part, on) { const X = DZ.exportPack; if (!X) return; const P = _dzExportParts(X); if (on) P.add(part); else P.delete(part); X.parts = P; _dzExportRender(); }
function _dzExportOpt(key, value) { const X = DZ.exportPack; if (!X) return; X[key] = value; _dzExportRender(); }
function _dzExportToggleObj(kind, id, on) { const X = DZ.exportPack; if (!X) return; const S = kind === 'dict' ? X.selDicts : X.selEngines; if (on) S.add(id); else S.delete(id); _dzExportRender(); }
function _dzExportShownObj(kind) {
  const X = DZ.exportPack, q = (X.filter || '').toLowerCase();
  const list = (kind === 'dict' ? X.dicts : X.engines) || [];
  return list.filter(o => !q || (o.name || '').toLowerCase().includes(q) || (o.dictionaries || []).join(' ').toLowerCase().includes(q));
}
function _dzExportSetObj(kind, on) {
  const X = DZ.exportPack; if (!X) return; const S = kind === 'dict' ? X.selDicts : X.selEngines;
  _dzExportShownObj(kind).forEach(o => { if (on) S.add(o.id); else S.delete(o.id); });
  _dzExportRender();
}
// How many objects the export would start from: the picked rules, engines and dictionaries of the ticked parts.
function _dzExportCount(X) {
  const P = _dzExportParts(X);
  return (P.has('rules') ? X.selected.size : 0) + (P.has('engines') ? (X.selEngines || new Set()).size : 0) + (P.has('dictionaries') ? (X.selDicts || new Set()).size : 0)
    + (P.has('framework') ? 1 : 0);
}
const DZ_EXPORT_FMT = { json: 'JSON pack', terraform: 'Terraform', both: 'JSON pack and Terraform' };
const DZ_EXPORT_PART = { dictionaries: 'Dictionaries', engines: 'Engines', rules: 'Rules', framework: 'ZIA policy framework' };
function _dzExportClose() { DZ.exportPack = null; DZ.step = 1; _dzRender(); }
function _dzExportToggle(k, on) { const X = DZ.exportPack; if (!X) return; if (on) X.selected.add(k); else X.selected.delete(k); _dzExportRender(); }
function _dzExportShown() {
  const X = DZ.exportPack, q = (X.filter || '').toLowerCase();
  return X.rules.filter(r => !q || (r.name || '').toLowerCase().includes(q) || (r.engines || []).join(' ').toLowerCase().includes(q));
}
function _dzExportSet(on) {
  const X = DZ.exportPack; if (!X) return;
  _dzExportShown().forEach(r => { const k = `${r.channel}:${r.id}`; if (on) X.selected.add(k); else X.selected.delete(k); });
  _dzExportRender();
}
function _dzExportRender() {
  const X = DZ.exportPack; if (!X) return;
  const label = (X.inventory && X.inventory.tenant_label) || 'the tenant';
  document.getElementById('dzTitle').textContent = 'Export from tenant as a pack';
  const steps = document.getElementById('dzSteps');
  steps.setAttribute('aria-label', 'Export steps');
  const at = X.result || X.running ? 1 : 0;
  steps.innerHTML = ['Pick what to export', 'Download'].map((s, i) => `<div class="dz-step ${i === at ? 'is-active' : (i < at ? 'is-done' : '')}" ${i === at ? 'aria-current="step"' : ''}><span class="n">${i < at ? '✓' : i + 1}</span>${s}</div>`).join('');
  document.getElementById('dzSub').textContent = at === 0
    ? `The DLP rules, custom engines and custom dictionaries in ${label}. Pick what to export and how: a JSON pack, Terraform, or both. Nothing is written to the tenant.`
    : 'Reading the tenant and building the pack. Nothing is written to the tenant.';
  const body = document.getElementById('dzBody');
  if (at === 1) {
    const R = X.result || {};
    const c = R.counts || {};
    const left = R.not_exported || [];
    const v = R.validation || { ok: true, problems: [] };
    body.innerHTML = `
      ${X.running ? `<div class="dz-card sev-info"><div class="bar"></div><div><div class="t" id="dzJobPhase">${_dzE(_dzJobPhase(DZ.job))}</div><div class="d">Elapsed <span id="dzJobElapsed">${_dzMMSS((DZ.job || {}).elapsed_seconds)}</span></div></div></div>` : ''}
      ${R.error ? `<div class="dz-card sev-error"><div class="bar"></div><div><div class="t">The export did not finish</div><div class="d">${_dzE(R.error)}</div></div></div>` : ''}
      ${R.status === 'ready' ? `<div class="dz-card sev-info"><div class="bar"></div><div><div class="t">Downloaded ${_dzE(R.filename || 'the pack')}</div>
        <div class="d">${R.framework_counts ? `ZIA policy framework: ${_dzE(Object.entries(R.framework_counts).map(([a, k]) => `${k} ${({ url: 'URL filtering', firewall: 'Cloud Firewall', ssl: 'SSL inspection', sandbox: 'Sandbox', dns: 'DNS Control', ftc: 'File Type Control' })[a] || a}`).join(', ') || 'no rules')}. ` : ''}${_dzN(c.rules || 0, 'rule')}, ${_dzN(c.engines || 0, 'custom engine')}, ${_dzN(c.dictionaries || 0, 'dictionary', 'dictionaries')} (${_dzN(c.clones || 0, 'clone')}) from ${_dzE(R.tenant_label || label)}${R.format && R.format !== 'json' ? `, as ${_dzE(DZ_EXPORT_FMT[R.format] || R.format)}` : ''}. ${R.format === 'terraform' ? '' : `Add the pack to the library under Advanced settings → Add a pack; it then shows here as a pack.${c.rules ? ' Deploying it creates every rule DISABLED and monitor-only; the pack keeps each rule\'s action and state as the tenant has them.' : ''}`}${R.format && R.format !== 'json' ? ` The Terraform workspace is for the zscaler/zia provider${c.rules ? '; every rule is created DISABLED' : ''}.${R.assessor_named ? '' : ' No assessor name was set, so <code>terraform apply</code> asks for <code>assessor</code>.'}` : ''}</div></div></div>` : ''}
      ${R.status === 'ready' && (R.part_files || []).length ? `<div class="dz-h">Download one part</div>
        <div class="dz-pick-tools">${R.part_files.map(f => `<button type="button" class="dz-btn" onclick="_dzExportFile('${_dzE(f.path)}')">${_dzE(DZ_EXPORT_PART[f.part] || f.part)} · ${f.format === 'terraform' ? 'Terraform (.tf)' : 'JSON'}</button>`).join('')}
          <button type="button" class="dz-btn" onclick="_dzExportFile('')">Everything (${_dzE(R.filename || '.zip')})</button></div>
        <div class="dz-note">A single .tf file is for review or to copy into an existing workspace; applying it needs the rest of the workspace (provider, variables), which is in the zip.</div>` : ''}
      ${R.status === 'ready' && R.referenced_only && ((R.referenced_only.engines || []).length || (R.referenced_only.dictionaries || []).length) ? `<div class="dz-card sev-warning"><div class="bar"></div><div><div class="t">Named, not included</div>
        <div class="d">Exported without what it uses, so these must already exist under the same names where this goes: ${_dzE([...(R.referenced_only.engines || []).map(n => `engine ${n}`), ...(R.referenced_only.dictionaries || []).map(n => `dictionary ${n}`)].slice(0, 12).join(', '))}${((R.referenced_only.engines || []).length + (R.referenced_only.dictionaries || []).length) > 12 ? '…' : ''}.</div></div></div>` : ''}
      ${R.status === 'ready' && !v.ok ? `<div class="dz-card sev-error"><div class="bar"></div><div><div class="t">The pack library would refuse this pack as it is</div><div class="d">${_dzE((v.problems || []).slice(0, 5).join('; '))}</div></div></div>` : ''}
      ${left.length ? `<div class="dz-h">Not in the pack<span class="count">${left.length}</span></div><div class="dz-rows">${left.map(d => `<div class="dz-row st-differs"><span class="ic" aria-hidden="true">!</span><div><div class="nm">${_dzE(d.name)}${d.channel ? ` <span class="dz-chip kind-channel">${_dzE(_dzChan(d.channel))}</span>` : ''}${d.field ? ` <span class="dz-chip">${_dzE(d.field)}</span>` : ''}</div><div class="rs">${_dzE(d.reason)}${(d.values || []).length ? ` (${_dzE(d.values.slice(0, 6).join(', '))}${d.values.length > 6 ? '…' : ''})` : ''}</div></div></div>`).join('')}</div>` : ''}
      <div class="dz-h">Export log</div>${_dzJobLiveHtml('Export log')}`;
    document.getElementById('dzFoot').innerHTML = `
      <div class="dz-summary">${X.running ? 'Reading the tenant, then building the pack…' : 'The list above is also in pack.json under not_exported.'}</div>
      <div class="dz-actions">
        ${X.running ? `<button type="button" class="dz-btn" id="dzJobStop" onclick="_dzCancelJob()" ${_dzStopAsked() ? 'disabled' : ''}>${_dzStopAsked() ? 'Stopping…' : 'Stop'}</button>` : `<button type="button" class="dz-btn" onclick="DZ.exportPack.result=null;_dzExportRender()">← Pick again</button><button type="button" class="dz-btn primary" onclick="_dzExportClose()">Done</button>`}
      </div>`;
    return;
  }
  const shown = _dzExportShown();
  const byChan = {};
  shown.forEach(r => { (byChan[r.channel] = byChan[r.channel] || []).push(r); });
  const row = r => { const k = `${r.channel}:${r.id}`; return `<label class="dz-row dz-pick ${X.selected.has(k) ? 'on' : ''}">
      <input type="checkbox" ${X.selected.has(k) ? 'checked' : ''} onchange="_dzExportToggle('${_dzE(k)}', this.checked)" aria-label="Export ${_dzE(r.name)}">
      <div><div class="nm">${_dzE(r.name)} <span class="dz-chip ${String(r.state).toUpperCase() === 'ENABLED' ? 'kind-policy' : ''}">${_dzE(String(r.state || '').toLowerCase() || 'state ?')}</span></div>
        <div class="rs">${(r.engines || []).length ? `engines: ${_dzE(r.engines.slice(0, 4).join(', '))}${r.engines.length > 4 ? '…' : ''}` : 'no engines'}${r.action ? ` · ${_dzE(String(r.action).toLowerCase())}` : ''}</div></div>
    </label>`; };
  const groups = Object.keys(byChan).map(ch => `<div class="dz-h" style="margin-top:0.8rem;">${_dzE(_dzChan(ch))}<span class="count">${byChan[ch].length}</span></div><div class="dz-rows">${byChan[ch].map(row).join('')}</div>`).join('');
  const errs = Object.entries(X.inventory.errors || {}).filter(([, v]) => v);
  const P = _dzExportParts(X), deps = X.deps !== false, fmt = X.format || 'json';
  const nDicts = (X.dicts || []).length, nEngines = (X.engines || []).length;
  const objRow = (kind, o) => { const S = kind === 'dict' ? X.selDicts : X.selEngines, on = S.has(o.id); return `<label class="dz-row dz-pick ${on ? 'on' : ''}">
      <input type="checkbox" ${on ? 'checked' : ''} onchange="_dzExportToggleObj('${kind}', '${_dzE(o.id)}', this.checked)" aria-label="Export ${_dzE(o.name)}">
      <div><div class="nm">${_dzE(o.name)}${kind === 'engine' && o.used === false ? ' <span class="dz-chip">no rule uses it</span>' : ''}</div>
        <div class="rs">${kind === 'engine' ? ((o.dictionaries || []).length ? `dictionaries: ${_dzE(o.dictionaries.slice(0, 4).join(', '))}${o.dictionaries.length > 4 ? '…' : ''}` : 'predefined dictionaries only') : _dzE(String(o.type || 'custom dictionary').toLowerCase().replace(/_/g, ' '))}</div>${kind === 'engine' ? _dzEngineExplain(o) : ''}</div>
    </label>`; };
  const objSection = (kind, title, list) => { const shownObj = _dzExportShownObj(kind); return `<div class="dz-h" style="margin-top:0.8rem;">${title}<span class="count">${list.length}</span>
      <button type="button" class="dz-link" onclick="_dzExportSetObj('${kind}', true)">Select all shown</button><button type="button" class="dz-link" onclick="_dzExportSetObj('${kind}', false)">Clear</button></div>
      <div class="dz-rows">${shownObj.map(o => objRow(kind, o)).join('') || `<div class="dz-empty">${list.length ? 'None match the filter.' : `The tenant has no custom ${title.toLowerCase()}.`}</div>`}</div>`; };
  const n = _dzExportCount(X);
  body.innerHTML = `
    <div class="dz-card sev-info"><div class="bar"></div><div><div class="t">${_dzN(X.rules.length, 'DLP rule')}, ${_dzN(nEngines, 'custom engine')} and ${_dzN(nDicts, 'custom dictionary', 'custom dictionaries')} in the tenant</div>
      <div class="d">Export rules, engines and dictionaries together or each on its own. Custom dictionaries go in full, clones as clones, predefined dictionaries and engines by name. Endpoint sub-rules come with their parent rule.${errs.length ? ` Not listed: ${_dzE(errs.map(([k, v]) => `${_dzChan(k)} (${v})`).join('; '))}.` : ''}</div></div></div>
    <fieldset class="dz-pick-tools" style="border:0;padding:0;margin:0 0 0.4rem;"><legend class="dz-h" style="padding:0;">What to export</legend>
      ${['dictionaries', 'engines', 'rules', 'framework'].map(part => `<label class="dz-chk"${part === 'framework' ? ' title="The URL filtering, Cloud Firewall, SSL inspection, Sandbox, DNS Control and File Type Control rules in scope, as a file the ZIA security baseline (Bulk changes) applies to another tenant."' : ''}><input type="checkbox" ${P.has(part) ? 'checked' : ''} onchange="_dzExportPart('${part}', this.checked)"> ${DZ_EXPORT_PART[part]}</label>`).join(' ')}
      <label class="dz-chk" title="On: engines bring the dictionaries they use, rules the engines and dictionaries they use. Off: only what you picked; what it uses is named and must already exist where it goes."><input type="checkbox" ${deps ? 'checked' : ''} onchange="_dzExportOpt('deps', this.checked)"> Include what they use</label>
    </fieldset>
    <fieldset class="dz-pick-tools" style="border:0;padding:0;margin:0 0 0.4rem;"><legend class="dz-h" style="padding:0;">Format</legend>
      ${['json', 'terraform', 'both'].map(f => `<label class="dz-chk"><input type="radio" name="dzExportFmt" value="${f}" ${fmt === f ? 'checked' : ''} onchange="_dzExportOpt('format', '${f}')"> ${DZ_EXPORT_FMT[f]}</label>`).join(' ')}
    </fieldset>
    ${fmt !== 'json' ? `<div class="dz-note">Terraform is a workspace for the official zscaler/zia provider, built like the Terraform hand-off: every rule is created DISABLED, and every object's description names the assessor (Scope assessment → Assessor name${String((_dzCreds() || {}).assessor || '').trim() ? `: ${_dzE(String(_dzCreds().assessor).trim())}` : '; not set, so terraform apply will ask for it'}).</div>` : ''}
    ${P.has('framework') ? '<div class="dz-note">The ZIA policy framework reads the URL filtering, Cloud Firewall, SSL inspection, Sandbox, DNS Control and File Type Control rules in scope on the Scope page (not the defaults or predefined rules) and saves them as zia_policy_framework.json, JSON whatever the format. Users, groups, locations and other objects of this tenant are left out and listed. To put it into another tenant, open Bulk changes, pick ZIA security baseline and load the file: every rule arrives disabled.</div>' : ''}
    ${!deps ? '<div class="dz-note">Without what they use, picked engines name their dictionaries and picked rules their engines; those must already exist under the same names where this is deployed.</div>' : ''}
    <div class="dz-pick-tools">
      <input type="text" class="dz-input" placeholder="Pack name (optional)" maxlength="120" value="${_dzE(X.name || '')}" oninput="DZ.exportPack.name=this.value" aria-label="Pack name">
    </div>
    <div class="dz-pick-tools">
      <input type="search" class="dz-input" placeholder="Filter by name" value="${_dzE(X.filter || '')}" oninput="_dzRefilter(DZ.exportPack, this, _dzExportRender)" aria-label="Filter rules">
      ${P.has('rules') ? '<button type="button" class="dz-link" onclick="_dzExportSet(true)">Select all shown</button><button type="button" class="dz-link" onclick="_dzExportSet(false)">Clear</button>' : ''}
    </div>
    ${P.has('dictionaries') ? objSection('dict', 'Dictionaries', X.dicts || []) : ''}
    ${P.has('engines') ? objSection('engine', 'Engines', X.engines || []) : ''}
    ${P.has('rules') ? (groups || '<div class="dz-empty">No rules match the filter.</div>') : ''}
    ${!P.size ? '<div class="dz-empty">Tick dictionaries, engines, rules or the ZIA policy framework above.</div>' : ''}`;
  document.getElementById('dzFoot').innerHTML = `
    <div class="dz-summary">${n ? `<strong style="color:var(--text);">${[P.has('dictionaries') ? _dzN((X.selDicts || new Set()).size, 'dictionary', 'dictionaries') : '', P.has('engines') ? _dzN((X.selEngines || new Set()).size, 'engine') : '', P.has('rules') ? _dzN(X.selected.size, 'rule') : '', P.has('framework') ? 'the ZIA policy framework' : ''].filter(Boolean).join(', ')}</strong> ticked, as ${_dzE(DZ_EXPORT_FMT[fmt])}. The export reads the tenant and writes nothing.` : 'Tick at least one dictionary, engine or rule, or the ZIA policy framework, to export.'}</div>
    <div class="dz-actions">
      <button type="button" class="dz-btn quiet" onclick="_dzExportClose()">Cancel</button>
      <button type="button" class="dz-btn primary" onclick="_dzExportRun()" ${n ? '' : 'disabled'}>Download ${fmt === 'json' ? 'pack' : fmt === 'terraform' ? 'Terraform' : 'pack and Terraform'} (${n})</button>
    </div>`;
}
async function _dzExportRun() {
  const X = DZ.exportPack; if (!X || !_dzExportCount(X) || X.running) return;
  const P = _dzExportParts(X);
  // Every rule ticked: the whole tenant (every channel); otherwise the ids per channel.
  const rules = {};
  if (P.has('rules') && X.selected.size !== X.rules.length) {
    X.rules.forEach(r => { if (X.selected.has(`${r.channel}:${r.id}`)) (rules[r.channel] = rules[r.channel] || []).push(r.id); });
  }
  // Every one ticked: "all"; otherwise the ids.
  const pick = (S, list) => (S && list && S.size === list.length ? 'all' : [...(S || [])]);
  const body = { rules, pack_name: X.name || '', parts: [...P], include_dependencies: X.deps !== false, format: X.format || 'json',
    dictionaries: pick(X.selDicts, X.dicts), engines: pick(X.selEngines, X.engines), ..._dzCreds(), ..._dzScope() };
  X.running = true; X.result = null; X.download = null; DZ.job = { logs: [] }; _dzExportRender();
  try {
    const snap = await _dzRunJob('/api/dlp-packs/export/start', body);
    if (snap.status === 'failed' || !snap.result) throw new Error(snap.error || 'The export ended without a result.');
    if (snap.result.status !== 'ready' || !snap.download) throw new Error(snap.result.error || snap.result.stopped || 'The export did not produce a pack.');
    const r = await fetch(snap.download, { cache: 'no-store' });
    if (!r.ok) throw new Error(`The pack could not be fetched (HTTP ${r.status}).`);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(await r.blob());
    a.download = snap.filename || snap.result.filename || 'exported_pack.zip';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    X.download = snap.download;
    X.result = snap.result;
    announce(`Pack downloaded: ${(snap.result.counts || {}).rules || 0} rule(s) with their engines and dictionaries.`);
  } catch (e) {
    X.result = { status: 'failed', error: e.message };
  } finally {
    X.running = false;
    if (DZ.exportPack === X) _dzExportRender();
  }
}

// A file the server serves as an attachment, saved under the name it gives.
async function _dzDownload(url, fallback) {
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) {
    let d = ''; try { d = (await r.json()).detail || ''; } catch (e) { /* not JSON */ }
    throw new Error(d || `HTTP ${r.status}`);
  }
  const cd = r.headers.get('Content-Disposition') || '', m = /filename="([^"]+)"/.exec(cd);
  const a = document.createElement('a');
  a.href = URL.createObjectURL(await r.blob());
  a.download = m ? m[1] : fallback;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  return a.download;
}

// The preflight on screen as a plan for change approval (PDF or Excel),
// rendered by the server from its own copy of this preflight.
function _dzPaper() {
  const l = String((navigator.languages && navigator.languages[0]) || navigator.language || '');
  return /^(en|es|fr)-(US|CA|MX)$/i.test(l) ? 'letter' : 'a4';
}
async function _dzPlanDownload(fmt) {
  const R = DZ.report; if (!R || !R.report_id) return;
  const url = `/api/dlp-packs/plan/${encodeURIComponent(R.report_id)}/export?format=${fmt}${fmt === 'pdf' ? `&page=${_dzPaper()}` : ''}`;
  try {
    const name = await _dzDownload(url, `deployment_plan.${fmt}`);
    announce(`Downloaded ${name}.`);
  } catch (e) { alert(`Could not download the plan: ${e.message}`); }
}

// DLP inventory (Excel): a read-only job over the channels in scope; the
// workbook comes from the finished job.
async function _dzInventoryXlsx() {
  if ((DZ.inventory || {}).running) return;
  const I = DZ.inventory = { running: true, note: 'Reading the tenant…' };
  DZ.job = { logs: [] };
  _dzRenderSelect();
  try {
    const snap = await _dzRunJob('/api/dlp-packs/inventory/start', { ..._dzCreds(), ..._dzScope() });
    if (snap.status === 'failed' || !snap.result) throw new Error(snap.error || 'The inventory ended without a result.');
    if (snap.result.status !== 'ready' || !snap.download) throw new Error(snap.result.error || snap.result.stopped || 'No workbook was made.');
    const name = await _dzDownload(snap.download, snap.filename || 'dlp_inventory.xlsx');
    const errs = Object.keys(snap.result.errors || {});
    I.note = `Downloaded ${name}.${errs.length ? ` Could not be read: ${errs.join(', ')} (named in the Summary sheet).` : ''}`;
    announce(I.note);
  } catch (e) {
    I.note = `The DLP inventory did not finish: ${e.message}`;
  } finally {
    I.running = false;
    if (DZ.inventory === I && !DZ.exportPack && DZ.step === 1) _dzRenderSelect();
  }
}

// One part of the finished export (its dictionaries, engines or rules, as
// JSON or a .tf file), or with no path the whole zip again.
async function _dzExportFile(path) {
  const X = DZ.exportPack; if (!X || !X.download) return;
  const url = path ? `${X.download}${X.download.includes('?') ? '&' : '?'}file=${encodeURIComponent(path)}` : X.download;
  try {
    const r = await fetch(url, { cache: 'no-store' });
    if (!r.ok) throw new Error(r.status === 404 ? 'The export is no longer kept (an hour after it finished); run it again.' : `HTTP ${r.status}`);
    const cd = r.headers.get('Content-Disposition') || '', m = /filename="([^"]+)"/.exec(cd);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(await r.blob());
    a.download = m ? m[1] : (path ? path.split('/').pop() : ((X.result || {}).filename || 'exported_pack.zip'));
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    announce(`Downloaded ${a.download}.`);
  } catch (e) { alert(`Could not download it: ${e.message}`); }
}

// ── Terraform hand-off ──────────────────────────────────────────────
// The same pack as a Terraform workspace for the official zscaler/zia
// provider, for customers whose platform team manages Zscaler as code.
// Opened through openToolTab('terraform', packIds) so it lives in its own
// tab like the other tools; the dialog below is what gets mirrored.
const TF = { packs: [], selected: new Set(), summaries: {}, busy: false, error: '', last: null };
function _tfEnsureModal() {
  if (document.getElementById('terraformModal')) return;
  const m = document.createElement('div');
  m.id = 'terraformModal'; m.setAttribute('role', 'dialog'); m.setAttribute('aria-modal', 'true'); m.setAttribute('aria-labelledby', 'terraformModalTitle');
  m.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:1000;overflow:auto;padding:2rem 1rem;';
  m.innerHTML = `<div style="max-width:1040px;margin:0 auto;background:var(--card-solid);border:1px solid var(--border);border-radius:14px;padding:1.4rem 1.6rem;box-shadow:0 20px 60px rgba(0,0,0,0.5);">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;margin-bottom:0.6rem;">
      <div><h2 id="terraformModalTitle" style="margin:0;">Terraform hand-off</h2>
        <p style="color:var(--dim);font-size:0.88rem;margin:0.3rem 0 0;max-width:80ch;">For customers whose platform team manages Zscaler as code. You get the same dictionaries, engines and rules as a Terraform workspace for the official zscaler/zia provider; they run it in their pipeline, and Terraform keeps it in state from then on.</p></div>
      <button class="btn btn-ghost" onclick="closeTerraformModal()" aria-label="Close" style="padding:0.4rem 0.8rem;font-size:0.85rem;white-space:nowrap;">✕ Close</button>
    </div>
    <div id="terraformBody"></div></div>`;
  document.body.appendChild(m);
  // Keyboard: Escape closes it, like every other dialog of the app (WCAG 2.1.2).
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && m.style.display === 'block') closeTerraformModal(); });
}
async function openTerraformModal(packIds) {
  _tfEnsureModal();
  const m = document.getElementById('terraformModal');
  if (m.style.display !== 'block') TF._opener = document.activeElement;   // focus goes back there on close
  m.style.display = 'block'; document.body.style.overflow = 'hidden';
  TF.error = '';
  _tfRender();
  const close = m.querySelector('button[aria-label="Close"]'); if (close) close.focus();
  try {
    if (!TF.packs.length) {
      const r = await fetch('/api/dlp-packs', { cache: 'no-store' });
      TF.packs = ((await r.json()).packs || []);
    }
    const want = (typeof packIds === 'string' ? packIds.split(',') : (packIds || [])).filter(Boolean);
    if (want.length) TF.selected = new Set(want.filter(id => TF.packs.some(p => p.id === id)));
    if (!TF.selected.size) TF.selected = new Set(TF.packs.filter(p => p.baseline).map(p => p.id));
    await Promise.all([...TF.selected].map(_tfLoadSummary));
  } catch (e) { TF.error = e.message; }
  _tfRender();
}
function closeTerraformModal() {
  const m = document.getElementById('terraformModal');
  if (m) m.style.display = 'none';
  document.body.style.overflow = '';
  const o = TF._opener; TF._opener = null;
  if (o && document.body.contains(o) && typeof o.focus === 'function') o.focus();
}
async function _tfLoadSummary(id) {
  if (TF.summaries[id]) return;
  try {
    const r = await fetch(`/api/dlp-packs/${encodeURIComponent(id)}/terraform`, { cache: 'no-store' });
    TF.summaries[id] = r.ok ? await r.json() : { error: `HTTP ${r.status}` };
  } catch (e) { TF.summaries[id] = { error: e.message }; }
}
async function _tfToggle(id, on) {
  if (on) { TF.selected.add(id); await _tfLoadSummary(id); } else TF.selected.delete(id);
  _tfRender();
}
// Gap mode needs tenant credentials; static never does. The operator
// picks either (TF.mode); with no pick, static is used.
function _tfCanGap() {
  const c = _dzCreds();
  const prof = !!(window.GD && GD.profile && GD.profileHasSecret);
  const has = k => !!String(c[k] || '').trim();
  // The chosen sign-in: the classic API needs the admin login plus its
  // password and API key (or a profile that remembers them); OneAPI the
  // client id plus its secret (or a remembered one). migrateCredBody blanks
  // the other method's fields, so client_id alone never decides it.
  if (c.auth_method === 'legacy') return has('username') && ((has('password') && has('api_key')) || prof);
  return has('client_id') && (has('client_secret') || prof);
}
// Static unless the operator picks gap: gap reads the tenant, and a
// tenant read is never chosen for them just because credentials are there.
function _tfMode() {
  return TF.mode === 'gap' && _tfCanGap() ? 'gap' : 'static';
}
function _tfSetMode(m) {
  if (m === 'gap' && !_tfCanGap()) { alert('Gap mode needs the tenant details on the assessment page (or a profile with a remembered secret). Static mode needs nothing.'); return; }
  TF.mode = m; _tfRender();
}
async function _tfDownload() {
  const ids = [...TF.selected];
  if (!ids.length) return;
  TF.busy = true; _tfRender();
  try { await _dzTerraform(ids, _tfMode()); }
  catch (e) { TF.last = { status: 'failed', error: e.message, logs: (DZ.job || {}).logs || [] }; }
  finally { TF.busy = false; _tfRender(); }
}
// _tfRender rebuilds the dialog's body (after the packs load, a pack is
// ticked, the mode changes or a download runs). Focus inside it would fall
// to <body>, out of the dialog (WCAG 2.4.3), so it goes back to the same
// control (same handler, name and value, same position among its kind),
// or to the dialog's Close button when that control is gone or disabled.
const _tfSig = e => [e.tagName, ...['onchange', 'onclick', 'name', 'value', 'id'].map(k => e.getAttribute(k) || '')].join('|');
function _tfFocusKey(host) {
  const a = document.activeElement;
  if (!a || a === host || !host.contains(a)) return null;
  const s = _tfSig(a);
  return { tag: a.tagName, s, n: [...host.querySelectorAll(a.tagName)].filter(e => _tfSig(e) === s).indexOf(a) };
}
function _tfRestoreFocus(host, key) {
  if (!key) return;
  const el = [...host.querySelectorAll(key.tag)].filter(e => _tfSig(e) === key.s)[key.n];
  if (el) el.focus({ preventScroll: true });
  const m = document.getElementById('terraformModal');
  if (m && !m.contains(document.activeElement)) { const c = m.querySelector('button[aria-label="Close"]'); if (c) c.focus({ preventScroll: true }); }
}
function _tfRender() {
  const host = document.getElementById('terraformBody');
  if (!host) return;
  const focusKey = _tfFocusKey(host);
  const mode = _tfMode();
  const sel = [...TF.selected];
  const packs = TF.packs.map(p => `<label class="tf-pack ${TF.selected.has(p.id) ? 'on' : ''}"><input type="checkbox" ${TF.selected.has(p.id) ? 'checked' : ''} onchange="_tfToggle('${_dzE(p.id)}', this.checked)"> <span><b>${_dzE(p.name || p.id)}</b>${p.baseline ? ' <span class="dz-chip kind-baseline">Policy pack</span>' : ''}<br><span class="d">${_dzN(p.dictionaries || 0, 'dictionary', 'dictionaries')} · ${_dzN(p.engines || 0, 'engine')} · ${_dzN(p.policies || 0, 'rule')}</span></span></label>`).join('');
  const sums = sel.map(id => {
    const s = TF.summaries[id];
    if (!s) return `<div class="tf-sum"><b>${_dzE(id)}</b> · loading…</div>`;
    if (s.error) return `<div class="tf-sum"><b>${_dzE(id)}</b> · ${_dzE(s.error)}</div>`;
    const ch = Object.entries(s.counts.channels || {}).map(([k, v]) => `${v} ${_dzChan(k)}`).join(', ');
    const files = (s.files || []).filter(f => !f.name.startsWith('.')).map(f => `<li><code>${_dzE(f.name)}</code> <span class="d">${_dzE(f.purpose)}</span></li>`).join('');
    return `<div class="tf-sum"><div class="tf-sum-h"><b>${_dzE(s.name)}</b> <span class="d">${s.counts.dictionaries} dictionaries · ${s.counts.engines} engines · ${s.counts.rules} rules (${_dzE(ch)})${s.counts.app_groups ? ` · ${s.counts.app_groups} app group(s)` : ''}</span></div>
      ${s.committed ? `<div class="d">Also in the repository as <code>${_dzE(s.path)}</code>, validated against the real provider on every commit. Those files name no assessor: <code>terraform apply</code> asks for the required <code>assessor</code> variable, the name every object's description carries. Gap mode adds <code>imports.tf</code> on top of these files.</div>` : ''}
      <details class="dz-fold"><summary>What is in the workspace (${(s.files || []).length} files)</summary><ul class="tf-files">${files}</ul></details></div>`;
  }).join('');
  host.innerHTML = `
    ${TF.error ? `<div class="dz-card sev-error"><div class="bar"></div><div><div class="t">Could not load packs</div><div class="d">${_dzE(TF.error)}</div></div></div>` : ''}
    <div class="dz-h">1 · Which packs</div>
    <div class="tf-packs">${packs || '<span class="d">Loading packs…</span>'}</div>
    <div class="dz-h">2 · Which hand-off</div>
    <div class="tf-choose-wrap"><table class="tf-choose">
      <caption>Pick by the customer's situation, not by what is quickest for you.</caption>
      <thead><tr><th scope="col">The customer…</th><th scope="col">Use</th><th scope="col">Why</th></tr></thead>
      <tbody>
        <tr><td>changes Zscaler in the ZIA portal, has no Terraform pipeline, and lets this tool write to the tenant</td><td><b>Deploy policy packs</b> (not this page)</td><td>The tool creates the objects directly, disabled and monitor-only. A Terraform workspace nobody runs is shelfware.</td></tr>
        <tr><td>manages Zscaler as code <em>and</em> the tenant already has DLP dictionaries, engines or rules (most production tenants)</td><td><b>Gap mode</b></td><td>Existing objects are imported, so the first <code>terraform plan</code> creates only what is missing instead of duplicates. Costs one read of the pack's objects on every channel in it (counts against the ZIA API rate limit).</td></tr>
        <tr><td>manages Zscaler as code on a new or empty tenant (nothing from these packs exists yet)</td><td><b>Static</b></td><td>There is nothing to import, so a tenant read buys nothing.</td></tr>
        <tr><td>will not share credentials, or you have no API access yet</td><td><b>Static</b></td><td>No tenant access at all. Tell the platform team to import any objects that already exist before their first apply, or Terraform creates duplicates.</td></tr>
        <tr><td>wants a design to review or a reference to diff against, not something to apply</td><td><b>Static</b></td><td>The workspace is the whole pack as written: easy to read in a pull request, independent of any tenant's state.</td></tr>
        <tr><td>uploaded their own pack and wants it transcribed as is</td><td><b>Static</b></td><td>Their pack, unchanged, in the provider's resources.</td></tr>
        <tr><td>edits DLP in the portal day to day and also wants Terraform</td><td><b>Neither yet</b></td><td>Agree who owns the objects first. Terraform reverts portal edits on the next apply unless they are folded back into the code.</td></tr>
      </tbody></table></div>
    <div class="tf-modes" role="radiogroup" aria-label="Terraform mode">
      <label class="tf-mode ${mode === 'gap' ? 'on' : ''}"><input type="radio" name="tfMode" value="gap" ${mode === 'gap' ? 'checked' : ''} ${_tfCanGap() ? '' : 'disabled'} onchange="_tfSetMode('gap')"> <span><span class="t">Gap mode ${mode === 'gap' ? '<span class="dz-chip kind-baseline">selected</span>' : ''}</span>
        <span class="d">Uses the tenant details from the assessment page. Zscaler Made Easy reads the tenant first and writes an <code>imports.tf</code> that adopts every object that already exists, so the platform team's first <code>terraform plan</code> is exactly the gap: creates only what is missing, imports the rest.<br><b>Use when</b> the tenant already has DLP objects and the team will apply this workspace. <b>Not when</b> the tenant is empty, credentials are off limits, or you only need a reference.${_tfCanGap() ? '' : ' Needs the tenant details (or a profile with a remembered secret) on the assessment page.'}</span></span></label>
      <label class="tf-mode ${mode === 'static' ? 'on' : ''}"><input type="radio" name="tfMode" value="static" ${mode === 'static' ? 'checked' : ''} onchange="_tfSetMode('static')"> <span><span class="t">Static ${mode === 'static' ? '<span class="dz-chip kind-baseline">selected</span>' : ''}</span>
        <span class="d">No tenant access, no credentials sent, no import blocks. The workspace describes the whole pack; on a tenant that already has some of it, the platform team imports those objects first or Terraform will try to create duplicates. <br><b>Use when</b> the tenant is new or empty, credentials cannot be shared, you are handing over a reference or design for review, or transcribing an uploaded pack as it is. <b>Not when</b> the tenant already has these objects and nobody will import them first.</span></span></label>
    </div>
    <div class="dz-h">3 · What you get</div>
    ${sums || '<div class="d">Select at least one pack.</div>'}
    <div class="dz-h">4 · Download and hand over</div>
    <div class="tf-actions">
      <button type="button" class="dz-btn primary" ${sel.length && !TF.busy ? '' : 'disabled'} onclick="_tfDownload()">${TF.busy ? 'Working…' : `Download workspace (${mode} mode, ${_dzN(sel.length, 'pack')})`}</button>
      <span class="d">One zip, one folder per pack. Give it to the customer's platform team with the note below.${mode === 'gap' ? ' Gap mode reads the tenant first (dictionaries, engines, the rules on every channel the pack uses): a minute or two, shown step by step below, and those reads count against the ZIA API rate limit.' : ''}</span>
    </div>
    ${TF.busy ? `
    <div class="dz-hero" style="margin-top:0.6rem;"><span class="dz-status busy">Working</span><div><div class="lead">${mode === 'gap' ? 'Reading the tenant, then building the workspace…' : 'Building the workspace…'}</div><div class="sub" id="dzJobPhase">${_dzE(_dzJobPhase(DZ.job || {}))}</div></div><div class="dz-elapsed" id="dzJobElapsed" aria-label="Elapsed">${_dzMMSS((DZ.job || {}).startedAt ? (Date.now() - DZ.job.startedAt) / 1000 : 0)}</div></div>
    <div class="dz-progress"><div class="bar"></div></div>
    ${_dzJobLiveHtml('Hand-off log')}
    <div class="dz-actions"><button type="button" class="dz-btn" id="dzJobStop" onclick="_dzCancelJob()" ${_dzStopAsked() ? 'disabled' : ''} title="Stop reading the tenant; nothing is downloaded">${_dzStopAsked() ? 'Stopping…' : 'Stop'}</button></div>` : ''}
    ${!TF.busy && TF.last ? (TF.last.status === 'ready'
      ? `<div class="dz-card sev-info" style="margin-top:0.6rem;"><div class="bar"></div><div><div class="t">Downloaded ${_dzE(TF.last.filename || 'the workspace')}</div><div class="d">${TF.last.mode === 'gap' ? `Gap mode against ${_dzE(TF.last.tenant_label || 'the tenant')}: ${_dzE(Object.entries(TF.last.gap || {}).map(([k, v]) => `${v} ${k}`).join(', ') || 'plan built')}. Objects the tenant already has are imported; the first terraform plan creates only the rest.` : 'Static mode: the whole pack, no tenant read.'} ${TF.last.elapsed_seconds ? `Took ${_dzMMSS(TF.last.elapsed_seconds)} min.` : ''}</div>
          ${(TF.last.logs || []).length ? `<details class="dz-fold"><summary>Log</summary><div class="dz-log">${_dzE(TF.last.logs.join('\n'))}</div></details>` : ''}</div></div>`
      : `<div class="dz-card sev-error" style="margin-top:0.6rem;"><div class="bar"></div><div><div class="t">The hand-off did not finish</div><div class="d">${_dzE(TF.last.error || TF.last.stopped || '')}</div>${(TF.last.logs || []).length ? `<details class="dz-fold" open><summary>Log</summary><div class="dz-log">${_dzE(TF.last.logs.join('\n'))}</div></details>` : ''}</div></div>`) : ''}
    <div class="dz-card sev-info"><div class="bar"></div><div><div class="t">What to tell the platform team</div><div class="d">
      <ol class="dz-next">
        <li>Unzip, open the pack folder, copy <code>terraform.tfvars.example</code> to <code>terraform.tfvars</code> and fill in the OneAPI client (or export <code>ZSCALER_CLIENT_ID</code>, <code>ZSCALER_CLIENT_SECRET</code>, <code>ZSCALER_VANITY_DOMAIN</code>). The client needs write access to DLP dictionaries, engines and the rule types in the pack.</li>
        <li>Run <code>terraform init</code>, then <code>terraform plan</code>. The plan is the review: it must list only creates (and imports in gap mode). Anything marked <em>update in place</em> is an object the customer customized; delete its import block to keep their version.</li>
        <li>Run <code>terraform apply</code>. Every rule arrives DISABLED; enabling is a deliberate, per-rule step in the ZIA portal or in the pack.</li>
        <li>From then on Terraform owns these objects. <code>terraform plan</code> later shows how the tenant has moved away from the reference; treat an enabled rule or a hardened action as progress to fold back into the pack, not as drift to revert.</li>
        <li>Requirements: Terraform ${_dzE((TF.summaries[sel[0]] || {}).terraform_version || '>= 1.5')}, provider ${_dzE((TF.summaries[sel[0]] || {}).provider || 'zscaler/zia')} ${_dzE((TF.summaries[sel[0]] || {}).provider_version || '~> 4.8')}.</li>
      </ol></div></div></div>`;
  _tfRestoreFocus(host, focusKey);
}
