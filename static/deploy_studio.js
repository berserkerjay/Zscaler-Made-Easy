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
  reuse:              { label: 'Already present', cls: 'st-reuse',   icon: '✓', help: 'The tenant already has this object with the same content. Nothing is written; the pack simply uses it.' },
  reuse_differs:      { label: 'Kept as-is',      cls: 'st-differs', icon: '≠', help: 'The tenant has an object with this name but different content (for a policy pack: the customer customized it, for example enabled the rule or hardened its action). The tenant version is kept and used; the pack version is not applied.' },
  conflict:           { label: 'Conflict',        cls: 'st-blocked', icon: '!', help: 'Two selected packs define this name differently, or it clashes with a predefined Zscaler object. Deselect one pack or rename it.' },
  blocked_dependency: { label: 'Skipped',         cls: 'st-blocked', icon: '–', help: 'Something this object needs is missing (a dictionary, an engine, an onboarded SaaS tenant, a licensed feature). It will not be created until that exists.' },
  skip_empty:         { label: 'Skipped',         cls: 'st-blocked', icon: '–', help: 'This dictionary has no phrases or patterns, so it could never match anything and is not created.' },
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
// pack ships rules for. A ticked channel the pack has no rule for gets a
// monitor-only extension rule carrying the pack's engines; an unticked
// channel is skipped. Containment rules (Cloud App Control, File Type,
// URL, SSL) are not part of the choice.
const DZ_DLP = ['web', 'endpoint', 'saas', 'email'];
const DZ_DLP_LABEL = { web: 'Inline Web DLP', endpoint: 'Endpoint DLP', saas: 'SaaS Security', email: 'Outbound Email DLP' };
const DZ_LS_CHANNELS = 'zassess_pack_channels';
function _dzLoadChannels() {
  try { DZ.channels = JSON.parse(localStorage.getItem(DZ_LS_CHANNELS) || '{}') || {}; } catch (e) { DZ.channels = {}; }
}
function _dzSaveChannels() {
  try { localStorage.setItem(DZ_LS_CHANNELS, JSON.stringify(DZ.channels)); } catch (e) { /* storage unavailable */ }
}
function _dzDefaultChannels(p) { return DZ_DLP.filter(c => (p.channels || {})[c]); }
function _dzChannelsFor(id) {
  const p = DZ.packs.find(x => x.id === id);
  if (!p) return [];
  if (!Array.isArray(DZ.channels[id])) return _dzDefaultChannels(p);
  return DZ.channels[id].filter(c => DZ_DLP.includes(c));
}
function _dzSetChannel(id, ch, on) {
  const cur = new Set(_dzChannelsFor(id));
  if (on) cur.add(ch); else cur.delete(ch);
  DZ.channels[id] = DZ_DLP.filter(c => cur.has(c));
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
  const skipped = DZ_DLP.filter(c => !chosen.has(c) && has(c)).length;
  return `<div class="dz-channels" onclick="event.stopPropagation()">
    <div class="dz-channels-h">Deploy the engines into <span class="d">${added ? `· ${_dzN(added, 'channel')} added with a monitor rule` : ''}${skipped ? ` · ${_dzN(skipped, 'packed channel')} skipped` : ''}</span></div>
    <div class="dz-chans">${boxes}</div></div>`;
}
function _dzTargetsSummary(ids) {
  return ids.map(id => {
    const p = DZ.packs.find(x => x.id === id) || { id };
    const ch = _dzChannelsFor(id);
    return `${_dzE(p.name || id)}: ${ch.length ? ch.map(c => _dzE(DZ_DLP_LABEL[c])).join(', ') : 'containment rules only'}`;
  }).join(' · ');
}

function _dzCreds() {
  if (typeof migrateCredBody === 'function') {
    const b = migrateCredBody(); delete b.customer_id; return b;
  }
  const v = id => (document.getElementById(id) || {}).value || '';
  return { cloud: v('cloud') || 'production', vanity_domain: v('vd'), client_id: v('cid'), client_secret: v('csec') };
}
const _dzE = s => escapeHtml(String(s == null ? '' : s));
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
          <h2 id="dzTitle">Deploy Policy Packs</h2>
          <p class="dz-sub" id="dzSub">Pick the packs to deploy. Everything is cross-checked against your tenant before anything is written.</p>
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
  const m = document.getElementById('dlpDeployModal');
  m.classList.add('is-open');
  document.body.style.overflow = 'hidden';
  DZ.step = 1; DZ.report = null; DZ.result = null; DZ.consent = false; DZ.error = ''; DZ.removal = null;
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
async function _dzSetWriteMode(enable) {
  const w = DZ.write || {};
  let confirm = '';
  if (enable) {
    if (!w.can_toggle) { alert(w.reason || 'Write mode can only be enabled from the start script on this server.'); return; }
    confirm = prompt(`Enable write mode for this server session?\n\nDeploy Studio will then CREATE objects in the tenant you approve. Every rule still arrives DISABLED, existing objects are never overwritten, and read-only returns when the server restarts.\n\nType ${w.confirm_phrase || 'YES_I_UNDERSTAND'} to continue:`, '') || '';
    if (!confirm) return;
  } else if (!window.confirm('Switch back to read-only? Preflight and the journey check keep working; deploying will be refused until write mode is enabled again.')) return;
  try {
    const r = await fetch('/api/write-mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enable, confirm }) });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((data.detail && (data.detail.cause || data.detail)) || `HTTP ${r.status}`);
    DZ.write = data;
    announce(data.enabled ? 'Write mode enabled for this session.' : 'Read-only mode.');
    // A plan made in read-only mode carries a read-only blocker; refresh it.
    if (DZ.report && DZ.step >= 2) { _dzRunPreflight(); return; }
  } catch (e) { alert(`Could not change write mode: ${e.message}`); }
  _dzRender();
}
function _dzWriteBanner() {
  const w = DZ.write;
  if (!w) return '';
  if (w.enabled) {
    return `<div class="dz-write on"><span class="dz-status ready">Write mode</span><div><div class="t">Deploying will create objects in the tenant you approve.</div>
      <div class="d">Every rule arrives DISABLED and existing objects are never overwritten. ${w.source === 'session' ? 'Enabled from this window; the server returns to read-only when it restarts.' : 'Set by the start script (ENABLE_WRITE_ACTIONS).'}</div></div>
      ${w.source === 'session' ? `<button type="button" class="dz-btn" onclick="_dzSetWriteMode(false)">Back to read-only</button>` : ''}</div>`;
  }
  return `<div class="dz-write off"><span class="dz-status warnings">Read-only</span><div><div class="t">Preflight, the plan and the journey check work; deploying is refused.</div>
    <div class="d">${w.can_toggle ? 'Enable write mode here when the customer has agreed to the plan. You will be asked to type a confirmation phrase.' : _dzE(w.reason || '')}</div></div>
    ${w.can_toggle ? `<button type="button" class="dz-btn primary" onclick="_dzSetWriteMode(true)">Enable write mode</button>` : ''}</div>`;
}

function closeDlpPacksModal() {
  const m = document.getElementById('dlpDeployModal');
  if (!m) return;
  m.classList.remove('is-open');
  document.body.style.overflow = '';
}

function _dzRender() {
  if (DZ.removal) return _dzRemovalRender();
  const steps = document.getElementById('dzSteps');
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

// ── Step 1: select ────────────────────────────────────────────────
function _dzRenderSelect() {
  const body = document.getElementById('dzBody');
  if (DZ.error && !DZ.packs.length) {
    body.innerHTML = `<div class="dz-card sev-error"><div class="bar"></div><div><div class="t">Something went wrong</div><div class="d">${_dzE(DZ.error)}</div></div></div>`;
  } else if (!DZ.packs.length) {
    body.innerHTML = `<div class="dz-empty">No policy packs found.<br><span style="font-size:0.8rem;">Drop a folder with <code>configs/dlp_*.json</code> in the project root, or see POLICY_PACKS.md.</span></div>`;
  } else {
    const cards = DZ.packs.map(p => {
      const sel = DZ.selected.has(p.id);
      const det = DZ.open.has(p.id) ? _dzDetailHtml(p.id) : '';
      return `
      <div class="dz-pack ${sel ? 'is-selected' : ''}" role="group" aria-label="${_dzE(p.name || p.id)}" onclick="_dzCardClick(event, '${_dzE(p.id)}')">
        <div class="dz-pack-top">
          <h3>${_dzE(p.name || p.id)}${p.version ? `<span class="v">v${_dzE(p.version)}</span>` : ''}</h3>
          <label class="dz-switch" title="${sel ? 'Deselect' : 'Select'} ${_dzE(p.name || p.id)}" onclick="event.stopPropagation()">
            <input type="checkbox" ${sel ? 'checked' : ''} onchange="_dzTogglePack('${_dzE(p.id)}', this.checked)" aria-label="Select ${_dzE(p.name || p.id)}">
            <span class="track"><span class="knob"></span></span>
          </label>
        </div>
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
          <button type="button" class="dz-link danger" title="Find what this pack put in the tenant (by its DLP-Check tag and its names) and remove it, in dependency order. Previews first; objects another rule or engine still uses are kept. Needs write mode." onclick="event.stopPropagation(); _dzRemove('${_dzE(p.id)}')">${(DZ.remove || {})[p.id] === 'busy' ? 'Working…' : 'Remove from tenant'}</button>
          ${p.id === 'zbp_source_code_baseline' ? `<button type="button" class="dz-link" title="Read the tenant's own source-code dictionaries (an Anchor and a Signal per language, paired by name), preview the pairing, then rebuild this pack from them: dictionaries keep their tenant names, each language gets one engine (Signal > N AND Anchor > 0), the old pack dictionaries and engines are dropped." onclick="event.stopPropagation(); _dzFromTenant('${_dzE(p.id)}')">${(DZ.fromTenant || {}).busy ? 'Reading tenant…' : 'Rebuild from tenant dictionaries'}</button>` : ''}
        </div>
        ${p.id === 'zbp_source_code_baseline' ? _dzFromTenantHtml() : ''}
        ${det}
        ${p.baseline ? _dzJourneyHtml(p.id) : ''}
      </div>`;
    }).join('');
    body.innerHTML = `
      ${_dzWriteBanner()}
      <div class="dz-grid">${cards}</div>
      <div class="dz-options">
        <div class="dz-option">
          <div><div class="t">Apply confidence tweaks</div><div class="d">Lets packs adjust confidence on existing dictionaries (e.g. Medical → Low). Each change is listed for approval.</div></div>
          <label class="dz-switch"><input type="checkbox" ${DZ.options.apply_tweaks ? 'checked' : ''} onchange="DZ.options.apply_tweaks=this.checked" aria-label="Apply confidence tweaks"><span class="track"><span class="knob"></span></span></label>
        </div>
        <div class="dz-option">
          <div><div class="t">Rank 0 (override rule ordering)</div><div class="d">New rules take precedence over rules made by lower-ranked admins. Only for resolving ordering conflicts.</div></div>
          <label class="dz-switch"><input type="checkbox" ${DZ.options.use_rank_0 ? 'checked' : ''} onchange="DZ.options.use_rank_0=this.checked" aria-label="Use rank 0"><span class="track"><span class="knob"></span></span></label>
        </div>
      </div>
      ${_dzDeploymentsHtml()}`;
  }
  const sel = DZ.packs.filter(p => DZ.selected.has(p.id));
  const tot = k => sel.reduce((a, p) => a + (p[k] || 0), 0);
  document.getElementById('dzFoot').innerHTML = `
    <div class="dz-summary">${sel.length
      ? `<strong style="color:var(--text);">${_dzN(sel.length, 'pack')}</strong> · ${tot('dictionaries')} dictionaries · ${tot('engines')} engines · ${tot('policies')} policies`
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
async function _dzTerraform(ids) {
  DZ.tfBusy = ids.length === 1 ? ids[0] : '*';
  if (DZ.step === 1) _dzRenderSelect();
  try {
    const creds = _dzCreds();
    const r = await fetch('/api/dlp-packs/terraform', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pack_ids: ids, use_rank_0: DZ.options.use_rank_0, channel_targets: _dzTargets(ids), ...creds }),
    });
    if (!r.ok) {
      const data = await r.json().catch(() => ({}));
      throw new Error(data.detail || `HTTP ${r.status}`);
    }
    const mode = r.headers.get('X-DLP-Check-Mode') || 'static';
    const blob = await r.blob();
    const cd = r.headers.get('Content-Disposition') || '';
    const m = /filename="([^"]+)"/.exec(cd);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = m ? m[1] : 'dlp-check-terraform.zip';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    announce(`Terraform workspace downloaded (${mode === 'gap' ? 'gap mode: existing objects will be imported' : 'static: no tenant credentials given'}).`);
  } catch (e) {
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
    ${objs.length ? `<details class="dz-fold"><summary>Objects not yet in place (${objs.length}${(b.objects || []).length > objs.length ? ' shown' : ''})</summary><ul class="dz-objs">${objs.map(o => `<li><span class="dz-chip kind-${_dzE(o.kind)}">${DZ_KIND[o.kind] || o.kind}</span> <span class="nm">${_dzE(o.name)}</span> <span class="st ${_dzE((DZ_POSITION[o.position] || {}).cls || '')}" title="${_dzE((DZ_POSITION[o.position] || {}).help || '')}">${_dzE((DZ_POSITION[o.position] || {}).label || o.position)}${o.drift && o.drift.length ? ` · ${_dzE(o.drift.join(', '))}` : ''}${o.action && o.position !== 'missing' && String(o.action).length <= 40 ? ` · ${_dzE(o.action)}` : ''}</span></li>`).join('')}</ul></details>` : ''}`;
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
  DZ.step = 2; DZ.report = null; DZ.error = ''; DZ.busy = true; DZ.consent = false;
  _dzRender();
  try {
    const r = await fetch('/api/dlp-packs/preflight', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pack_ids: [...DZ.selected], ...DZ.options, channel_targets: _dzTargets([...DZ.selected]), ..._dzCreds() }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
    DZ.report = data;
    announce(`Preflight ${data.status}: ${data.will_create} changes, ${data.warnings.length} warnings.`);
  } catch (e) {
    DZ.error = e.message;
  } finally {
    DZ.busy = false; _dzRender();
  }
}

function _dzRow(i, statusKey, extra) {
  const st = DZ_STATUS[statusKey] || { label: statusKey, cls: 'st-reuse', icon: '•' };
  const reason = extra || i.reason || i.error || '';
  return `<div class="dz-row ${st.cls}">
    <span class="ic" aria-hidden="true">${st.icon}</span>
    <div><div class="nm">${_dzE(i.name)}</div>${reason ? `<div class="rs">${_dzE(reason)}</div>` : ''}</div>
    <div class="tags"><span class="dz-chip kind-${i.kind}" title="${_dzE(DZ_KIND_HELP[i.kind] || '')}">${DZ_KIND[i.kind] || i.kind}</span>${i.detail && i.detail.channel ? `<span class="dz-chip kind-channel" title="${_dzE(DZ_CHANNEL_HELP[i.detail.channel] || '')}">${_dzE(_dzChan(i.detail.channel))}</span>` : ''}${i.extension ? `<span class="dz-chip kind-baseline" title="Added by your channel selection: a monitor-only rule carrying the pack's engines on a channel the pack ships no rule for.">channel add-on</span>` : ''}<span class="dz-chip" title="${_dzE(st.help || '')}">${st.label}</span>${(i.packs || []).slice(0, 2).map(p => `<span class="dz-chip" title="Defined by pack ${_dzE(p)}">${_dzE(p)}</span>`).join('')}</div>
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
  const blocked = [...by('conflict'), ...by('blocked_dependency'), ...by('skip_empty')];
  const reused = [...by('reuse'), ...by('noop')];
  const lead = { ready: 'Ready to deploy', warnings: 'Ready, with things to review', blocked: 'Deployment is blocked' }[R.status];
  const sub = `${_dzN(creates.length, 'change')}${restores.length ? ` (${_dzN(restores.length, 'converge overwrite')})` : ''} · ${_dzN(differs.length, 'existing object')} kept as-is · ${_dzN(blocked.length, 'item')} skipped · ${_dzN(reused.length, 'item')} already in place`;
  const t = R.tenant || {};
  body.innerHTML = `
    <div class="dz-hero">
      <span class="dz-status ${R.status}">${lead}</span>
      <div><div class="lead">${_dzE(R.tenant_label || 'tenant')}</div><div class="sub">${sub}</div></div>
    </div>
    <div class="dz-kv">
      <div><div class="k">Will create</div><div class="v">${creates.filter(i => i.status === 'create').length}</div></div>
      <div><div class="k">${restores.length ? 'Will overwrite / modify' : 'Will modify'}</div><div class="v">${creates.filter(i => i.status === 'modify' || i.status === 'restore').length}</div></div>
      <div><div class="k">Skipped</div><div class="v">${blocked.length}</div></div>
      <div><div class="k">Tenant rules</div><div class="v">${t.rules ?? '–'}<span style="font-size:0.75rem;color:var(--dim);font-weight:500;"> / ${t.rule_cap || 127}</span></div></div>
    </div>
    ${(R.blockers || []).map(b => `<div class="dz-card sev-error" style="margin-top:0.9rem;"><div class="bar"></div><div><div class="t">Blocked</div><div class="d">${_dzE(b)}</div></div></div>`).join('')}
    <details class="dz-fold dz-howto"><summary><div class="dz-h">How to read this plan</div></summary>
      <ul class="dz-note">
        <li><strong>Nothing has been written.</strong> This is a dry run against the live tenant.</li>
        <li><strong>Impact cards</strong> say what changes for the tenant as a whole: greenfield or brownfield, rules inserted at the top of the policy, enforcing actions, activation.</li>
        <li><strong>Existing objects are never overwritten.</strong> A rule the customer enabled or hardened, or a dictionary they tuned, is kept exactly as it is and shown as <em>Kept as-is</em>. Only what is missing gets created.</li>
        <li><strong>Tenant prerequisites</strong> are things the tenant must already have (a predefined dictionary, an onboarded SaaS tenant, a licensed feature). Missing ones skip only the rules that need them.</li>
        <li><strong>Flow</strong> shows how dictionaries feed engines feed rules; hover any box to trace it. <strong>List</strong> groups the same objects by what will happen to them. Hover any status chip for what it means.</li>
        <li>Every rule ships <strong>DISABLED</strong>, so deploying never affects users. Enable rules in the portal after tuning.</li>
        <li><strong>Two ways to close the gap.</strong> <em>Review &amp; approve</em> creates the missing objects from here (write mode needed). <em>Hand off as Terraform</em> gives a platform team the same objects as a Terraform workspace whose first <code>terraform plan</code> is exactly this list.</li>
      </ul></details>
    ${(R.impacts || []).length ? `<div class="dz-h">Impact on this tenant</div>` : ''}
    ${(R.impacts || []).map(i => `<div class="dz-card sev-${_dzE(i.severity)}"><div class="bar"></div><div><div class="t">${_dzE(i.title)}</div><div class="d">${_dzE(i.detail)}</div></div></div>`).join('')}
    ${_dzDepsHtml(R.dependencies)}
    ${_dzViewToggle()}
    ${(DZ.view || 'flow') === 'flow' ? _dzFlowHtml(items, null) : `
    ${_dzSection('Converge mode — will be overwritten with the policy pack', restores)}
    ${_dzSection('Changes that will be written', creates.filter(i => i.status !== 'restore'))}
    ${_dzSection('Already exist, customized by the customer — kept as-is', differs)}
    ${_dzSection('Skipped — dependency or conflict', blocked)}
    ${_dzSection('Already in place — nothing to do', reused, { open: false })}`}`;
  if ((DZ.view || 'flow') === 'flow') _dzFlowZoom(0);
  _dzFlowSyncTab(items, null);
  foot.innerHTML = `
    <div class="dz-summary">${R.status === 'blocked' ? 'Resolve the blockers above, then run preflight again.' : 'Nothing has been written yet.'}</div>
    <div class="dz-actions">
      <button type="button" class="dz-btn" onclick="DZ.step=1;_dzRender()">← Back</button>
      <button type="button" class="dz-btn" onclick="_dzRunPreflight()">Re-run</button>
      <button type="button" class="dz-btn" title="Close this gap with Terraform instead: opens the hand-off page for the selected packs (what you get, how to run it, download in gap mode so terraform plan shows exactly these changes)." onclick="openToolTab('terraform', [...DZ.selected].join(','))">Hand off as Terraform</button>
      <button type="button" class="dz-btn primary" ${R.status === 'blocked' ? 'disabled' : ''} onclick="DZ.step=3;DZ.consent=false;_dzRender()">Review &amp; approve <span aria-hidden="true">→</span></button>
    </div>`;
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
    ${warns.length ? `<div class="dz-h">Warnings<span class="count">${warns.length}</span></div><div class="dz-rows">${warns.map(w => `<div class="dz-row st-differs"><span class="ic" aria-hidden="true">!</span><div class="rs" style="margin-top:0.25rem;color:var(--text);">${_dzE(w)}</div><div></div></div>`).join('')}</div>` : ''}
    ${_dzSection('Exactly what will be written', writes)}
    <div class="dz-card sev-info"><div class="bar"></div><div><div class="t">Before you approve, confirm with the customer</div><div class="d">
      1. The tenant name above is the right tenant. &nbsp;2. The customer has seen this list and agreed. &nbsp;3. The customer knows an admin must activate changes in the ZIA portal afterwards, and that every new rule arrives disabled.
      ${restores.length ? ' &nbsp;4. Converge mode is on: the objects listed above will be overwritten with the policy pack. If the customer changed any of them on purpose, stop and deploy without converge mode.' : ''}
    </div></div></div>
    <div class="dz-consent">
      <input type="checkbox" id="dzConsent" ${DZ.consent ? 'checked' : ''} onchange="DZ.consent=this.checked;_dzRenderApprove()">
      <label for="dzConsent">I've reviewed this plan and the warnings above, and I authorize these changes to <strong>${_dzE(R.tenant_label || 'the tenant')}</strong>. ${restores.length
        ? `<strong>${_dzN(restores.length, 'customized object')} will be overwritten</strong> with the policy pack definition (converge mode); every other existing object is left untouched.`
        : 'Existing objects are never overwritten;'} Changes are activated in ZIA automatically when the deploy completes.<br><code>plan ${_dzE((R.plan_hash || '').slice(0, 12))}</code></label>
    </div>`;
  const writeOff = DZ.write && !DZ.write.enabled;
  document.getElementById('dzFoot').innerHTML = `
    <div class="dz-summary">${writeOff ? 'The server is read-only: enable write mode to deploy.' : (DZ.consent ? 'Ready when you are.' : 'Tick the box to enable deployment.')}</div>
    <div class="dz-actions">
      <button type="button" class="dz-btn" onclick="DZ.step=2;_dzRender()">← Back</button>
      ${writeOff && DZ.write.can_toggle ? `<button type="button" class="dz-btn" onclick="_dzSetWriteMode(true)">Enable write mode</button>` : ''}
      <button type="button" class="dz-btn primary" ${DZ.consent && R.status !== 'blocked' && !writeOff ? '' : 'disabled'} onclick="_dzApply()">Deploy to tenant</button>
    </div>`;
}

// ── Step 4: deploy ────────────────────────────────────────────────
async function _dzApply() {
  DZ.step = 4; DZ.busy = true; DZ.result = null; DZ.error = '';
  _dzRender();
  try {
    const r = await fetch('/api/dlp-packs/apply', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pack_ids: [...DZ.selected], ...DZ.options, channel_targets: _dzTargets([...DZ.selected]), plan_hash: DZ.report.plan_hash, confirm: true, verify: true, ..._dzCreds() }),
    });
    const data = await r.json().catch(() => ({}));
    if (r.status === 409 && data.status) { DZ.result = data; }
    else if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
    else DZ.result = data;
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
    body.innerHTML = `<div class="dz-hero"><span class="dz-status busy">Deploying</span><div><div class="lead">Writing to ${_dzE((DZ.report || {}).tenant_label || 'tenant')}…</div><div class="sub">Dictionaries first, then engines, then rules. Each item is isolated — one failure won't stop the rest.</div></div></div><div class="dz-progress"><div class="bar"></div></div>`;
    foot.innerHTML = `<div class="dz-summary">Please keep this window open.</div><div class="dz-actions"><button class="dz-btn primary" disabled>Deploying…</button></div>`;
    return;
  }
  if (DZ.error) {
    body.innerHTML = `<div class="dz-card sev-error"><div class="bar"></div><div><div class="t">Deployment didn't start</div><div class="d">${_dzE(DZ.error)}</div></div></div>`;
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
  const lead = { applied: 'Deployed successfully', partial: 'Deployed with some failures', failed: 'Deployment failed' }[X.status] || X.status;
  const cls = { applied: 'ready', partial: 'warnings', failed: 'blocked' }[X.status] || 'warnings';
  const ver = X.verification || {};
  const verRows = Object.entries(ver).map(([id, v]) => {
    const ok = v && v.all_good;
    const d = v.dictionaries || {}, e = v.engines || {};
    const detail = v.error ? v.error : `dictionaries ${d.ok ?? '?'}/${d.total ?? '?'}, engines ${e.ok ?? '?'}/${e.total ?? '?'}${(d.missing || []).length ? `; missing: ${d.missing.join(', ')}` : ''}${Object.keys(d.mismatched || {}).length ? `; mismatched: ${Object.keys(d.mismatched).join(', ')}` : ''}`;
    return _dzRow({ name: id, kind: 'policy', packs: [] }, ok ? 'created' : 'failed', (ok ? 'Verified — tenant matches the pack. ' : 'Verification found differences. ') + detail).replace('kind-policy">Policy', 'kind-policy">Pack');
  }).join('');
  body.innerHTML = `
    <div class="dz-hero"><span class="dz-status ${cls}">${lead}</span><div><div class="lead">${_dzN(s.created || 0, 'object')} created${s.restored ? ` · ${s.restored} overwritten` : ''} · ${s.modified || 0} modified · ${s.reused || 0} reused · ${s.skipped || 0} skipped · ${s.failed || 0} failed</div><div class="sub">${X.elapsed_seconds || 0}s</div></div></div>
    ${X.activation && X.activation.activated ? `<div class="dz-card sev-info" style="margin-top:0.9rem;"><div class="bar"></div><div><div class="t">Activated in ZIA</div><div class="d">The changes were activated automatically, so they are live now.</div></div></div>` : ''}
    ${X.activation_required ? `<div class="dz-card sev-warning" style="margin-top:0.9rem;"><div class="bar"></div><div><div class="t">Activate to take effect</div><div class="d">ZIA saved these changes as pending and automatic activation did not run${X.activation && X.activation.error ? ` (${_dzE(X.activation.error)})` : ''}. Open the ZIA Admin Portal and click Activate (or run ziaActivator) — users are unaffected until you do.</div></div></div>` : ''}
    <div class="dz-card sev-info"><div class="bar"></div><div><div class="t">What to do next</div><div class="d">
      <ol class="dz-next">
        <li><strong>Activate</strong> in the ZIA Admin Portal so the objects exist for traffic (they are still disabled).</li>
        <li><strong>Enable rules one at a time</strong> in Policy &gt; Data Loss Prevention, starting with the monitor-only ones, and raise their severity once incidents look right.</li>
        <li><strong>Review incidents</strong> after a few days, then tune. Changes the customer makes in the portal are kept; fold the good ones back into the pack so the next tenant starts from them.</li>
        <li><strong>Measure the journey</strong> on the next visit: run the assessment, or click <em>Where is this tenant?</em> on the pack card. It shows the stage reached (Foundation → Policies deployed → Visibility → Containment → Enforcement) and exactly which rules to enable or harden next.</li>
        <li>If the customer manages Zscaler with Terraform, use <strong>Export Terraform</strong> on the review step to hand them the same configuration with state.</li>
      </ol></div></div></div>
    ${_dzViewToggle()}
    ${(DZ.view || 'flow') === 'flow' ? _dzFlowHtml((DZ.report || {}).items || [], results) : `
    ${_dzSection('Failed', results.filter(r => r.status === 'failed'), { fn: r => _dzRow(r, 'failed', r.error) })}
    ${_dzSection('Overwritten with the policy pack (converge mode)', results.filter(r => r.status === 'restored'), { fn: r => _dzRow(r, 'restored', `${r.id ? `ID ${r.id}` : ''}${r.drift && r.drift.length ? ` · ${r.drift.join(', ')}` : ''}`) })}
    ${_dzSection('Created & modified', results.filter(r => r.status === 'created' || r.status === 'modified'), { fn: r => _dzRow(r, r.status, r.id ? `ID ${r.id}` : '') })}
    ${_dzSection('Skipped', results.filter(r => r.status === 'skipped'), { fn: r => _dzRow(r, 'skipped', r.reason) })}
    ${_dzSection('Reused from tenant', results.filter(r => r.status === 'reused'), { open: false, fn: r => _dzRow(r, 'reused', r.id ? `ID ${r.id}` : '') })}`}
    ${verRows ? `<div class="dz-h">Post-deploy verification</div><div class="dz-rows">${verRows}</div>` : ''}
    ${(X.logs || []).length ? `<details class="dz-fold"><summary><div class="dz-h">Log</div></summary><div class="dz-log">${_dzE(X.logs.join('\n'))}</div></details>` : ''}`;
  if ((DZ.view || 'flow') === 'flow') _dzFlowZoom(0);
  _dzFlowSyncTab((DZ.report || {}).items || [], results);
  foot.innerHTML = `
    <div class="dz-summary">plan ${_dzE((X.plan_hash || '').slice(0, 12))}${X.deployment_id ? ' · recorded for undo' : ''}${X.deployment_error ? ` · ${_dzE(X.deployment_error)}` : ''}</div>
    <div class="dz-actions">
      ${X.deployment_id ? `<button type="button" class="dz-btn" title="Delete everything this deployment just created" onclick="_dzUndoLast()">Undo this deployment</button>` : ''}
      <button type="button" class="dz-btn" onclick="DZ.step=1;DZ.report=null;DZ.result=null;_dzRender()">Deploy more</button>
      <button type="button" class="dz-btn primary" onclick="closeDlpPacksModal()">Done</button>
    </div>`;
}


// ── Remove a deployed pack — a wizard that mirrors deploy ──────────
// Preview (find what the pack put in the tenant, draw the flow, explain
// what goes and what is kept) -> Approve -> Remove. The same flow diagram
// as a deploy shows how each dictionary feeds its engines feed its rules.
const RM_KIND = { policy: 'rule', app_group: 'application group', engine: 'engine', dictionary: 'dictionary' };
const RM_STEPS = ['Preview', 'Approve', 'Remove'];

async function _dzRemove(id) {
  const pack = (DZ.packs || []).find(x => x.id === id) || { id, name: id };
  DZ.remove = DZ.remove || {}; DZ.remove[id] = 'busy'; _dzRenderSelect();
  let plan;
  try {
    const r = await fetch('/api/dlp-packs/removal/preflight', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pack_ids: [id], ..._dzCreds() }),
    });
    plan = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((plan.detail && (plan.detail.cause || plan.detail)) || `HTTP ${r.status}`);
  } catch (e) {
    DZ.remove[id] = null; _dzRenderSelect();
    alert(`Could not scan the tenant for ${pack.name || id}: ${e.message}`);
    return;
  }
  DZ.remove[id] = null;
  if (plan.status === 'blocked') { alert((plan.blockers || ['Could not read the tenant.']).join('\n')); _dzRenderSelect(); return; }
  DZ.removal = { id, pack, plan, step: 1, result: null };
  _dzRemovalRender();
}

function _dzRemovalClose() { DZ.removal = null; DZ.step = 1; _dzRender(); }

function _dzRemovalRender() {
  const R = DZ.removal; if (!R) return;
  const steps = document.getElementById('dzSteps');
  steps.innerHTML = RM_STEPS.map((s, i) => {
    const n = i + 1, cls = n === R.step ? 'is-active' : (n < R.step ? 'is-done' : '');
    return `<div class="dz-step ${cls}" ${n === R.step ? 'aria-current="step"' : ''}><span class="n">${n < R.step ? '✓' : n}</span>${s}</div>`;
  }).join('');
  const subs = { 1: `Removing ${R.pack.name || R.id}: what it put in ${_dzE(R.plan.tenant_label || 'the tenant')}, and how it flows. Nothing is deleted yet.`,
                 2: 'Review, then approve. Deletion is in dependency order and needs write mode.',
                 3: DZ.busy ? 'Removing — keep this window open.' : 'Removal finished.' };
  document.getElementById('dzSub').textContent = subs[R.step];
  ({ 1: _dzRemovalPreview, 2: _dzRemovalApprove, 3: _dzRemovalDone })[R.step]();
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
      <div class="rs">${i.status === 'keep' ? `Kept — ${_dzE(i.keep)}` : (i.match === 'name' ? 'Removed — matched by name (no DLP-Check tag; confirm it is yours)' : 'Removed — carries this pack’s DLP-Check tag')}</div></div>
  </div>`;
  const removeSorted = remove.slice().sort((a, b) => (order[a.kind] ?? 9) - (order[b.kind] ?? 9) || a.name.localeCompare(b.name));
  body.innerHTML = `
    ${!remove.length ? `<div class="dz-card sev-info"><div class="bar"></div><div><div class="t">Nothing to remove</div><div class="d">No objects in the tenant carry this pack’s DLP-Check tag or its names.${keep.length ? ` ${keep.length} matching object(s) are kept because something else still uses them.` : ''}</div></div></div>` : `
    <div class="dz-flow-hint" style="margin-bottom:0.6rem;">How ${_dzE(R.pack.name || R.id)} flows through the tenant: each dictionary feeds its engines, which feed the rules on every channel. Red is removed; grey is kept because another rule or engine still uses it.</div>
    ${_dzFlowHtml(items, null, { standalone: true })}
    <div class="dz-h" style="margin-top:1rem;">Will remove<span class="count">${remove.length}</span></div>
    <div class="dz-rows">${removeSorted.map(row).join('')}</div>
    ${keep.length ? `<div class="dz-h" style="margin-top:1rem;">Kept (still used elsewhere)<span class="count">${keep.length}</span></div><div class="dz-rows">${keep.map(row).join('')}</div>` : ''}`}
    <div class="dz-actions">
      <button type="button" class="dz-btn quiet" onclick="_dzRemovalClose()">Cancel</button>
      <button type="button" class="dz-btn quiet" onclick="_dzRemovalReport()" ${remove.length ? '' : 'disabled'}>Print / Save as PDF</button>
      <button type="button" class="dz-btn primary" onclick="DZ.removal.step=2;_dzRemovalRender()" ${remove.length ? '' : 'disabled'}>Continue to approve</button>
    </div>`;
  if (remove.length) _dzFlowZoom(0);
}

function _dzRemovalApprove() {
  const R = DZ.removal, body = document.getElementById('dzBody');
  const remove = (R.plan.items || []).filter(i => i.status === 'remove');
  const nameOnly = remove.filter(i => i.match === 'name');
  const writeOn = !!(DZ.write && DZ.write.enabled);
  body.innerHTML = `
    ${_dzWriteBanner()}
    <div class="dz-card sev-high"><div class="bar"></div><div>
      <div class="t">Remove ${remove.length} object(s) from ${_dzE(R.plan.tenant_label || 'the tenant')}</div>
      <div class="d">Deleted in dependency order: rules, then endpoint application groups, then engines, then dictionaries — activating between tiers so the engines and dictionaries the pack owns are no longer referenced and actually delete. Objects another rule or engine still uses are left alone. Activation runs automatically.</div>
    </div></div>
    ${nameOnly.length ? `<div class="dz-card sev-medium"><div class="bar"></div><div><div class="t">${nameOnly.length} object(s) matched by name only</div><div class="d">These carry no DLP-Check tag: ${_dzE(nameOnly.map(i => i.name).join(', '))}. Confirm they are yours before removing.</div></div></div>` : ''}
    <label class="dz-consent"><input type="checkbox" id="rmConsent" ${R.consent ? 'checked' : ''} onchange="DZ.removal.consent=this.checked;_dzRemovalRender()"> I understand this permanently deletes ${remove.length} object(s) from ${_dzE(R.plan.tenant_label || 'the tenant')}.</label>
    <div class="dz-actions">
      <button type="button" class="dz-btn quiet" onclick="DZ.removal.step=1;_dzRemovalRender()">Back</button>
      <button type="button" class="dz-btn quiet" onclick="_dzRemovalReport()">Print / Save as PDF</button>
      <button type="button" class="dz-btn danger" ${writeOn && R.consent ? '' : 'disabled'} title="${writeOn ? '' : 'Enable write mode first'}" onclick="_dzRemovalApply()">Remove now</button>
    </div>`;
}

function _dzRemovalDone() {
  const R = DZ.removal, body = document.getElementById('dzBody'), data = R.result || {};
  const s = data.summary || {};
  const kept = data.kept || [];
  const line = (label, n, cls) => n ? `<div class="dz-row ${cls}"><span class="ic">•</span><div><div class="nm">${n} ${label}</div></div></div>` : '';
  body.innerHTML = `
    <div class="dz-card ${data.status === 'removed' ? 'sev-info' : 'sev-medium'}"><div class="bar"></div><div>
      <div class="t">Removal ${_dzE(data.status || '')}</div>
      <div class="d">${data.activation && data.activation.activated ? 'Activated in ZIA automatically — the deletions are live.' : (data.activation_required ? `Automatic activation did not run${data.activation && data.activation.error ? ` (${_dzE(data.activation.error)})` : ''}; activate in ZIA to make the deletions live.` : 'Nothing needed activation.')}</div></div></div>
    <div class="dz-rows">
      ${line('deleted', s.deleted, 'st-ok')}${line('already gone', s.gone, 'st-reuse')}${line('left alone', s.skipped, 'st-differs')}${line('failed', s.failed, 'st-fail')}${line('still present', s.still_present, 'st-fail')}
    </div>
    ${(data.results || []).filter(x => x.status === 'failed' || x.status === 'skipped' || x.status === 'still_present').length ? `<div class="dz-h" style="margin-top:0.8rem;">Not removed</div><div class="dz-rows">${(data.results || []).filter(x => x.status === 'failed' || x.status === 'skipped' || x.status === 'still_present').map(x => `<div class="dz-row st-fail"><span class="ic">!</span><div><div class="nm">${_dzE(x.name)}</div><div class="rs">${_dzE(x.error || x.reason || '')}</div></div></div>`).join('')}</div>` : ''}
    ${kept.length ? `<div class="dz-h" style="margin-top:0.8rem;">Kept (still in use)<span class="count">${kept.length}</span></div><div class="dz-rows">${kept.map(i => `<div class="dz-row st-reuse"><span class="ic">↺</span><div><div class="nm">${_dzE(RM_KIND[i.kind] || i.kind)}: ${_dzE(i.name)}</div><div class="rs">${_dzE(i.keep || '')}</div></div></div>`).join('')}</div>` : ''}
    <div class="dz-actions">
      <button type="button" class="dz-btn primary" onclick="_dzRemovalClose()">Back to packs</button>
    </div>`;
}

async function _dzRemovalApply() {
  const R = DZ.removal; if (!R) return;
  const remove = (R.plan.items || []).filter(i => i.status === 'remove');
  // Second confirmation (the consent checkbox was the first): a final,
  // explicit yes naming the count and tenant before anything is deleted.
  if (!window.confirm(`Final confirmation.\n\nPermanently delete ${remove.length} object(s) that ${R.pack.name || R.id} put in ${R.plan.tenant_label || 'this tenant'}?\n\nThis cannot be undone from here. Click OK to remove, or Cancel to stop.`)) return;
  DZ.busy = true; R.step = 3; _dzRemovalRender();
  try {
    const r = await fetch('/api/dlp-packs/removal/apply', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pack_ids: [R.id], plan_hash: R.plan.plan_hash, confirm: true, ..._dzCreds() }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((data.detail && (data.detail.cause || data.detail)) || `HTTP ${r.status}`);
    R.result = data;
    announce(`Removal ${data.status}.`);
  } catch (e) {
    R.result = { status: 'failed', summary: {}, results: [{ status: 'failed', name: R.pack.name || R.id, error: e.message }] };
  } finally {
    DZ.busy = false; _dzRemovalRender();
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
      <td>${i.status === 'keep' ? esc(i.keep) : (i.match === 'name' ? 'Matched by name only (no DLP-Check tag) — confirm ownership' : 'Carries this pack’s DLP-Check provenance tag')}</td>
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
    <div class="noprint"><button class="btn" onclick="window.print()">Print / Save as PDF</button></div>
    <h1>Removal plan — ${esc(R.pack.name || R.id)}</h1>
    <p class="sub">Tenant ${esc(R.plan.tenant_label || '')} · generated ${new Date().toLocaleString()}</p>
    <div class="stat"><div><b>${remove}</b> to remove</div><div><b>${keep}</b> kept (still in use)</div></div>
    <p>This is the plan previewed in DLP-Check. Removal deletes objects in dependency order — rules, then endpoint application groups, then engines, then dictionaries — so nothing is deleted while something still points at it. An engine a surviving rule still uses, and a dictionary a surviving engine still uses, are kept and listed below. Predefined Zscaler dictionaries are never removed. DLP-Check activates the changes in ZIA automatically as the removal runs, so the deletions are live when it finishes.</p>
    <table><thead><tr><th>Type</th><th>Name</th><th>Channel</th><th>Decision</th><th>Why</th></tr></thead><tbody>${rows}</tbody></table>
    <p class="method">Objects are matched to the pack by the DLP-Check provenance tag written into each object’s description at deploy time, and by the names the pack defines. Name-only matches carry no tag and are flagged for confirmation.</p>
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
  const chans = ct => Object.entries(ct || {}).map(([pid, chs]) => `${_dzE(pid)}: ${(chs || []).map(c => DZ_DLP_LABEL[c] || c).join(', ') || 'as packed'}`).join(' · ');
  const list = rows.slice(0, 12).map(d => {
    const done = d.remaining === 0 && d.created > 0;
    const busy = DZ.undoBusy === d.id;
    const res = DZ.undoResult && DZ.undoResult.id === d.id ? DZ.undoResult : null;
    return `<div class="dz-row ${done ? 'st-reuse' : 'st-ok'}">
      <span class="ic" aria-hidden="true">${done ? '↺' : '✓'}</span>
      <div><div class="nm">${_dzE(fmt(d.at))} · ${_dzE(d.tenant_label || '')} · ${_dzE((d.packs || []).join(', '))}</div>
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
  const kinds = Object.entries(d.created_by_kind || {}).map(([k, n]) => _dzN(n, ...(DZ_KIND_PLURAL[k] || [k]))).join(', ');
  if (!window.confirm(`Undo the deployment of ${(d.packs || []).join(', ')} made ${new Date(d.at).toLocaleString()} in ${d.tenant_label}?\n\nThis DELETES the ${d.remaining} object${d.remaining === 1 ? '' : 's'} it created (${kinds}) from the tenant, in dependency order. Objects the customer renamed, and engines or dictionaries another rule still uses, are left alone and reported.\n\nThe tenant fields on the page must be for ${d.tenant_label}.`)) return;
  DZ.undoBusy = id; DZ.undoResult = null; _dzRenderSelect();
  try {
    const r = await fetch(`/api/deployments/${encodeURIComponent(id)}/undo`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirm: true, ..._dzCreds() }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((data.detail && (data.detail.cause || data.detail)) || `HTTP ${r.status}`);
    const s = data.summary || {};
    const parts = [];
    if (s.deleted) parts.push(`${s.deleted} deleted`);
    if (s.gone) parts.push(`${s.gone} already gone`);
    if (s.still_present) parts.push(`${s.still_present} still present`);
    if (s.skipped) parts.push(`${s.skipped} left alone (renamed)`);
    if (s.failed) parts.push(`${s.failed} could not be deleted`);
    const detail = (data.results || []).filter(x => x.status === 'failed' || x.status === 'skipped' || x.status === 'still_present').map(x => `${x.name}: ${x.error || x.reason}`).join('; ');
    DZ.undoResult = { id, text: `Undo ${data.status}: ${parts.join(', ') || 'nothing to do'}.${detail ? ' ' + detail : ''}${data.activation_required ? ' Activate in ZIA to make the deletions live.' : ''}` };
    announce(`Undo ${data.status}.`);
    await _dzLoadDeployments();
  } catch (e) {
    DZ.undoResult = { id, text: `Undo failed: ${e.message}` };
  } finally {
    DZ.undoBusy = null; if (DZ.step === 1) _dzRenderSelect();
  }
}
async function _dzUndoLast() {
  const id = DZ.result && DZ.result.deployment_id;
  if (!id) return;
  await _dzLoadDeployments();
  DZ.step = 1; DZ.report = null; DZ.result = null; _dzRender();
  _dzUndo(id);
}

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
    if (r) { n.result = r.status; n.resultText = r.error || r.reason || (r.id ? `ID ${r.id}` : ''); }
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
  btn.innerHTML = '<span aria-hidden="true">\u{1F4E6}</span> Deploy Policy Packs';
  btn.setAttribute('aria-label', 'Deploy DLP policy packs with dependency checks, impact review, and approval');
})();


// ── Terraform hand-off ──────────────────────────────────────────────
// The same pack as a Terraform workspace for the official zscaler/zia
// provider, for customers whose platform team manages Zscaler as code.
// Opened through openToolTab('terraform', packIds) so it lives in its own
// tab like the other tools; the dialog below is what gets mirrored.
const TF = { packs: [], selected: new Set(), summaries: {}, busy: false, error: '' };
function _tfEnsureModal() {
  if (document.getElementById('terraformModal')) return;
  const m = document.createElement('div');
  m.id = 'terraformModal'; m.setAttribute('role', 'dialog'); m.setAttribute('aria-modal', 'true'); m.setAttribute('aria-labelledby', 'terraformModalTitle');
  m.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);backdrop-filter:blur(6px);z-index:1000;overflow:auto;padding:2rem 1rem;';
  m.innerHTML = `<div style="max-width:1040px;margin:0 auto;background:var(--card-solid);border:1px solid var(--border);border-radius:14px;padding:1.4rem 1.6rem;box-shadow:0 20px 60px rgba(0,0,0,0.5);">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;margin-bottom:0.6rem;">
      <div><h2 id="terraformModalTitle" style="margin:0;">Terraform hand-off</h2>
        <p style="color:var(--dim);font-size:0.88rem;margin:0.3rem 0 0;max-width:80ch;">For customers whose platform team manages Zscaler as code. You get the same dictionaries, engines and rules as a Terraform workspace for the official zscaler/zia provider; they run it in their pipeline, and Terraform keeps it in state from then on.</p></div>
      <button class="btn btn-ghost" onclick="closeTerraformModal()" aria-label="Close" style="padding:0.4rem 0.8rem;font-size:0.85rem;white-space:nowrap;">✕ Close</button>
    </div>
    <div id="terraformBody"></div></div>`;
  document.body.appendChild(m);
}
async function openTerraformModal(packIds) {
  _tfEnsureModal();
  const m = document.getElementById('terraformModal');
  m.style.display = 'block'; document.body.style.overflow = 'hidden';
  TF.error = '';
  _tfRender();
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
function _tfMode() {
  const c = _dzCreds();
  const prof = (window.GD && GD.profile && GD.profileHasSecret);
  return (c.client_id && (c.client_secret || prof)) || (c.client_id && prof) ? 'gap' : 'static';
}
async function _tfDownload() {
  const ids = [...TF.selected];
  if (!ids.length) return;
  TF.busy = true; _tfRender();
  try { await _dzTerraform(ids); } finally { TF.busy = false; _tfRender(); }
}
function _tfRender() {
  const host = document.getElementById('terraformBody');
  if (!host) return;
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
      ${s.committed ? `<div class="d">Also in the repository as <code>${_dzE(s.path)}</code>, validated against the real provider on every commit. Gap mode adds <code>imports.tf</code> on top of these files.</div>` : ''}
      <details class="dz-fold"><summary>What is in the workspace (${(s.files || []).length} files)</summary><ul class="tf-files">${files}</ul></details></div>`;
  }).join('');
  host.innerHTML = `
    ${TF.error ? `<div class="dz-card sev-error"><div class="bar"></div><div><div class="t">Could not load packs</div><div class="d">${_dzE(TF.error)}</div></div></div>` : ''}
    <div class="dz-h">1 · Which packs</div>
    <div class="tf-packs">${packs || '<span class="d">Loading packs…</span>'}</div>
    <div class="dz-h">2 · Which mode</div>
    <div class="tf-modes">
      <div class="tf-mode ${mode === 'gap' ? 'on' : ''}"><div class="t">Gap mode ${mode === 'gap' ? '<span class="dz-chip kind-baseline">selected</span>' : ''}</div>
        <div class="d">Uses the tenant details from the assessment page. DLP-Check reads the tenant first and writes an <code>imports.tf</code> that adopts every object that already exists, so the platform team's first <code>terraform plan</code> is exactly the gap: creates only what is missing, imports the rest. Choose this when you have credentials.</div></div>
      <div class="tf-mode ${mode === 'static' ? 'on' : ''}"><div class="t">Static ${mode === 'static' ? '<span class="dz-chip kind-baseline">selected</span>' : ''}</div>
        <div class="d">No tenant access needed. The workspace describes the whole pack; on a tenant that already has some of it, the platform team imports those objects first or Terraform will try to create duplicates. Choose this to hand over a reference before you have credentials.</div></div>
    </div>
    ${mode === 'static' ? '<div class="d" style="margin:0.3rem 0 0.6rem;">To get gap mode, fill in the tenant fields (or pick a profile with a remembered secret) on the assessment page and reopen this page.</div>' : ''}
    <div class="dz-h">3 · What you get</div>
    ${sums || '<div class="d">Select at least one pack.</div>'}
    <div class="dz-h">4 · Download and hand over</div>
    <div class="tf-actions">
      <button type="button" class="dz-btn primary" ${sel.length && !TF.busy ? '' : 'disabled'} onclick="_tfDownload()">${TF.busy ? 'Generating…' : `Download workspace (${mode} mode, ${_dzN(sel.length, 'pack')})`}</button>
      <span class="d">One zip, one folder per pack. Give it to the customer's platform team with the note below.</span>
    </div>
    <div class="dz-card sev-info"><div class="bar"></div><div><div class="t">What to tell the platform team</div><div class="d">
      <ol class="dz-next">
        <li>Unzip, open the pack folder, copy <code>terraform.tfvars.example</code> to <code>terraform.tfvars</code> and fill in the OneAPI client (or export <code>ZSCALER_CLIENT_ID</code>, <code>ZSCALER_CLIENT_SECRET</code>, <code>ZSCALER_VANITY_DOMAIN</code>). The client needs write access to DLP dictionaries, engines and the rule types in the pack.</li>
        <li>Run <code>terraform init</code>, then <code>terraform plan</code>. The plan is the review: it must list only creates (and imports in gap mode). Anything marked <em>update in place</em> is an object the customer customized; delete its import block to keep their version.</li>
        <li>Run <code>terraform apply</code>. Every rule arrives DISABLED; enabling is a deliberate, per-rule step in the ZIA portal or in the pack.</li>
        <li>From then on Terraform owns these objects. <code>terraform plan</code> later shows how the tenant has moved away from the reference; treat an enabled rule or a hardened action as progress to fold back into the pack, not as drift to revert.</li>
        <li>Requirements: Terraform ${_dzE((TF.summaries[sel[0]] || {}).terraform_version || '>= 1.5')}, provider ${_dzE((TF.summaries[sel[0]] || {}).provider || 'zscaler/zia')} ${_dzE((TF.summaries[sel[0]] || {}).provider_version || '~> 4.8')}.</li>
      </ol></div></div></div>`;
}
