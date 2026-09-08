// ── Policy Pack Deploy Studio ────────────────────────────────────
// Select packs → preflight against the live tenant → review the exact
// plan, warnings and impacts → give explicit consent → deploy.
// State lives in DZ; every step re-renders from it.

const DZ = {
  packs: [], selected: new Set(), details: {}, open: new Set(),
  options: { use_rank_0: false, apply_tweaks: true },
  step: 1, report: null, result: null, busy: false, consent: false, error: '',
};
const DZ_STEPS = ['Select packs', 'Preflight', 'Approve', 'Deploy'];
const DZ_STATUS = {
  create:             { label: 'Will create',     cls: 'st-create',  icon: '+' },
  modify:             { label: 'Will modify',     cls: 'st-modify',  icon: '✎' },
  reuse:              { label: 'Already present', cls: 'st-reuse',   icon: '✓' },
  reuse_differs:      { label: 'Kept as-is',      cls: 'st-differs', icon: '≠' },
  conflict:           { label: 'Conflict',        cls: 'st-blocked', icon: '!' },
  blocked_dependency: { label: 'Skipped',         cls: 'st-blocked', icon: '–' },
  skip_empty:         { label: 'Skipped',         cls: 'st-blocked', icon: '–' },
  noop:               { label: 'No change',       cls: 'st-reuse',   icon: '✓' },
  // apply results
  created:  { label: 'Created',  cls: 'st-ok',      icon: '✓' },
  modified: { label: 'Modified', cls: 'st-ok',      icon: '✓' },
  reused:   { label: 'Reused',   cls: 'st-reuse',   icon: '✓' },
  skipped:  { label: 'Skipped',  cls: 'st-blocked', icon: '–' },
  failed:   { label: 'Failed',   cls: 'st-blocked', icon: '✕' },
};
const DZ_KIND = { dictionary: 'Dictionary', engine: 'Engine', policy: 'Policy', tweak: 'Tweak' };

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
      <header class="dz-head">
        <div>
          <h2 id="dzTitle">Deploy Policy Packs</h2>
          <p class="dz-sub" id="dzSub">Pick the packs to deploy. Everything is cross-checked against your tenant before anything is written.</p>
        </div>
        <button type="button" class="dz-close" onclick="closeDlpPacksModal()" aria-label="Close">✕</button>
      </header>
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
  DZ.step = 1; DZ.report = null; DZ.result = null; DZ.consent = false; DZ.error = '';
  _dzRender();
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

function closeDlpPacksModal() {
  const m = document.getElementById('dlpDeployModal');
  if (!m) return;
  m.classList.remove('is-open');
  document.body.style.overflow = '';
}

function _dzRender() {
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
        <p>${_dzE(p.description || 'No description provided.')}</p>
        <div class="dz-meta">
          <span class="dz-chip kind-dictionary">${_dzN(p.dictionaries || 0, 'dictionary', 'dictionaries')}</span>
          <span class="dz-chip kind-engine">${_dzN(p.engines || 0, 'engine')}</span>
          <span class="dz-chip kind-policy">${_dzN(p.policies || 0, 'policy', 'policies')}</span>
        </div>
        <button type="button" class="dz-link" onclick="event.stopPropagation(); _dzToggleDetail('${_dzE(p.id)}')">${DZ.open.has(p.id) ? 'Hide details' : 'Show details'}</button>
        ${det}
      </div>`;
    }).join('');
    body.innerHTML = `
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
      </div>`;
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
function _dzDetailHtml(id) {
  const d = DZ.details[id];
  if (!d) return `<div class="dz-detail">Loading…</div>`;
  if (d.error) return `<div class="dz-detail" style="color:var(--fail);">${_dzE(d.error)}</div>`;
  const li = (items, f) => items.length ? items.map(f).join('') : '<li>none</li>';
  return `<div class="dz-detail" onclick="event.stopPropagation()">
    <div><strong>Dictionaries</strong><ul>${li(d.dictionaries.items, x => `<li><span>${_dzE(x.name)}</span><span>${x.type}${x.proximity ? ` · prox ${x.proximity}` : ''}</span></li>`)}</ul></div>
    <div><strong>Engines</strong><ul>${li(d.engines.items, x => `<li><span>${_dzE(x.name)}</span></li>`)}</ul></div>
    <div><strong>Policies</strong><ul>${li(d.policies.items, x => `<li><span>${_dzE(x.name)}</span><span>${_dzE(x.action)}</span></li>`)}</ul></div>
  </div>`;
}

// ── Step 2: preflight ─────────────────────────────────────────────
async function _dzRunPreflight() {
  DZ.step = 2; DZ.report = null; DZ.error = ''; DZ.busy = true; DZ.consent = false;
  _dzRender();
  try {
    const r = await fetch('/api/dlp-packs/preflight', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pack_ids: [...DZ.selected], ...DZ.options, ..._dzCreds() }),
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
    <div class="tags"><span class="dz-chip kind-${i.kind}">${DZ_KIND[i.kind] || i.kind}</span><span class="dz-chip">${st.label}</span>${(i.packs || []).slice(0, 2).map(p => `<span class="dz-chip">${_dzE(p)}</span>`).join('')}</div>
  </div>`;
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
  const creates = [...by('create'), ...by('modify')];
  const differs = by('reuse_differs');
  const blocked = [...by('conflict'), ...by('blocked_dependency'), ...by('skip_empty')];
  const reused = [...by('reuse'), ...by('noop')];
  const lead = { ready: 'Ready to deploy', warnings: 'Ready, with things to review', blocked: 'Deployment is blocked' }[R.status];
  const sub = `${_dzN(creates.length, 'change')} · ${_dzN(differs.length, 'existing object')} kept as-is · ${_dzN(blocked.length, 'item')} skipped · ${_dzN(reused.length, 'item')} already in place`;
  const t = R.tenant || {};
  body.innerHTML = `
    <div class="dz-hero">
      <span class="dz-status ${R.status}">${lead}</span>
      <div><div class="lead">${_dzE(R.tenant_label || 'tenant')}</div><div class="sub">${sub}</div></div>
    </div>
    <div class="dz-kv">
      <div><div class="k">Will create</div><div class="v">${creates.filter(i => i.status === 'create').length}</div></div>
      <div><div class="k">Will modify</div><div class="v">${creates.filter(i => i.status === 'modify').length}</div></div>
      <div><div class="k">Skipped</div><div class="v">${blocked.length}</div></div>
      <div><div class="k">Tenant rules</div><div class="v">${t.rules ?? '–'}<span style="font-size:0.75rem;color:var(--dim);font-weight:500;"> / ${t.rule_cap || 127}</span></div></div>
    </div>
    ${(R.blockers || []).map(b => `<div class="dz-card sev-error" style="margin-top:0.9rem;"><div class="bar"></div><div><div class="t">Blocked</div><div class="d">${_dzE(b)}</div></div></div>`).join('')}
    ${(R.impacts || []).length ? `<div class="dz-h">Impact on this tenant</div>` : ''}
    ${(R.impacts || []).map(i => `<div class="dz-card sev-${_dzE(i.severity)}"><div class="bar"></div><div><div class="t">${_dzE(i.title)}</div><div class="d">${_dzE(i.detail)}</div></div></div>`).join('')}
    ${_dzViewToggle()}
    ${(DZ.view || 'flow') === 'flow' ? _dzFlowHtml(items, null) : `
    ${_dzSection('Changes that will be written', creates)}
    ${_dzSection('Already exist with different content — tenant version kept', differs)}
    ${_dzSection('Skipped — dependency or conflict', blocked)}
    ${_dzSection('Already in place — nothing to do', reused, { open: false })}`}`;
  if ((DZ.view || 'flow') === 'flow') _dzFlowZoom(0);
  foot.innerHTML = `
    <div class="dz-summary">${R.status === 'blocked' ? 'Resolve the blockers above, then run preflight again.' : 'Nothing has been written yet.'}</div>
    <div class="dz-actions">
      <button type="button" class="dz-btn" onclick="DZ.step=1;_dzRender()">← Back</button>
      <button type="button" class="dz-btn" onclick="_dzRunPreflight()">Re-run</button>
      <button type="button" class="dz-btn primary" ${R.status === 'blocked' ? 'disabled' : ''} onclick="DZ.step=3;DZ.consent=false;_dzRender()">Review &amp; approve <span aria-hidden="true">→</span></button>
    </div>`;
}

// ── Step 3: approve ───────────────────────────────────────────────
function _dzRenderApprove() {
  const R = DZ.report;
  const items = R.items || [];
  const writes = items.filter(i => i.status === 'create' || i.status === 'modify');
  const warns = R.warnings || [];
  const body = document.getElementById('dzBody');
  body.innerHTML = `
    <div class="dz-hero">
      <span class="dz-status ${R.status}">${R.status === 'warnings' ? 'Review the warnings' : 'Ready'}</span>
      <div><div class="lead">${_dzN(writes.length, 'change')} to ${_dzE(R.tenant_label || 'your tenant')}</div>
      <div class="sub">${_dzN([...DZ.selected].length, 'pack')} · ${R.options.use_rank_0 ? 'rank 0 on' : 'standard ranking'} · ${R.options.apply_tweaks ? 'confidence tweaks on' : 'no confidence tweaks'}</div></div>
    </div>
    ${warns.length ? `<div class="dz-h">Warnings<span class="count">${warns.length}</span></div><div class="dz-rows">${warns.map(w => `<div class="dz-row st-differs"><span class="ic" aria-hidden="true">!</span><div class="rs" style="margin-top:0.25rem;color:var(--text);">${_dzE(w)}</div><div></div></div>`).join('')}</div>` : ''}
    ${_dzSection('Exactly what will be written', writes)}
    <div class="dz-consent">
      <input type="checkbox" id="dzConsent" ${DZ.consent ? 'checked' : ''} onchange="DZ.consent=this.checked;_dzRenderApprove()">
      <label for="dzConsent">I've reviewed this plan and the warnings above, and I authorize these changes to <strong>${_dzE(R.tenant_label || 'the tenant')}</strong>. Existing objects are never overwritten; changes still need activation in ZIA afterwards.<br><code>plan ${_dzE((R.plan_hash || '').slice(0, 12))}</code></label>
    </div>`;
  document.getElementById('dzFoot').innerHTML = `
    <div class="dz-summary">${DZ.consent ? 'Ready when you are.' : 'Tick the box to enable deployment.'}</div>
    <div class="dz-actions">
      <button type="button" class="dz-btn" onclick="DZ.step=2;_dzRender()">← Back</button>
      <button type="button" class="dz-btn primary" ${DZ.consent && R.status !== 'blocked' ? '' : 'disabled'} onclick="_dzApply()">Deploy to tenant</button>
    </div>`;
}

// ── Step 4: deploy ────────────────────────────────────────────────
async function _dzApply() {
  DZ.step = 4; DZ.busy = true; DZ.result = null; DZ.error = '';
  _dzRender();
  try {
    const r = await fetch('/api/dlp-packs/apply', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pack_ids: [...DZ.selected], ...DZ.options, plan_hash: DZ.report.plan_hash, confirm: true, verify: true, ..._dzCreds() }),
    });
    const data = await r.json().catch(() => ({}));
    if (r.status === 409 && data.status) { DZ.result = data; }
    else if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
    else DZ.result = data;
    const s = DZ.result.summary || {};
    announce(`Deployment ${DZ.result.status}: ${s.created || 0} created, ${s.failed || 0} failed.`);
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
    <div class="dz-hero"><span class="dz-status ${cls}">${lead}</span><div><div class="lead">${_dzN(s.created || 0, 'object')} created · ${s.modified || 0} modified · ${s.reused || 0} reused · ${s.skipped || 0} skipped · ${s.failed || 0} failed</div><div class="sub">${X.elapsed_seconds || 0}s</div></div></div>
    ${X.activation_required ? `<div class="dz-card sev-warning" style="margin-top:0.9rem;"><div class="bar"></div><div><div class="t">Activate to take effect</div><div class="d">ZIA saved these changes as pending. Open the ZIA Admin Portal and click Activate (or run ziaActivator) — users are unaffected until you do.</div></div></div>` : ''}
    ${_dzViewToggle()}
    ${(DZ.view || 'flow') === 'flow' ? _dzFlowHtml((DZ.report || {}).items || [], results) : `
    ${_dzSection('Failed', results.filter(r => r.status === 'failed'), { fn: r => _dzRow(r, 'failed', r.error) })}
    ${_dzSection('Created & modified', results.filter(r => r.status === 'created' || r.status === 'modified'), { fn: r => _dzRow(r, r.status, r.id ? `ID ${r.id}` : '') })}
    ${_dzSection('Skipped', results.filter(r => r.status === 'skipped'), { fn: r => _dzRow(r, 'skipped', r.reason) })}
    ${_dzSection('Reused from tenant', results.filter(r => r.status === 'reused'), { open: false, fn: r => _dzRow(r, 'reused', r.id ? `ID ${r.id}` : '') })}`}
    ${verRows ? `<div class="dz-h">Post-deploy verification</div><div class="dz-rows">${verRows}</div>` : ''}
    ${(X.logs || []).length ? `<details class="dz-fold"><summary><div class="dz-h">Log</div></summary><div class="dz-log">${_dzE(X.logs.join('\n'))}</div></details>` : ''}`;
  if ((DZ.view || 'flow') === 'flow') _dzFlowZoom(0);
  foot.innerHTML = `
    <div class="dz-summary">plan ${_dzE((X.plan_hash || '').slice(0, 12))}</div>
    <div class="dz-actions">
      <button type="button" class="dz-btn" onclick="DZ.step=1;DZ.report=null;DZ.result=null;_dzRender()">Deploy more</button>
      <button type="button" class="dz-btn primary" onclick="closeDlpPacksModal()">Done</button>
    </div>`;
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
  { key: 'policy',     title: 'Policies' },
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
    add(it.kind, it.name, it.status, { reason: it.reason, packs: it.packs, warnings: it.warnings, tenant: it.tenant });
  }
  for (const it of items) {
    if (it.kind === 'tweak') continue;
    for (const dep of (it.depends_on || [])) {
      const i = dep.indexOf(':');
      const dk = dep.slice(0, i), dn = dep.slice(i + 1);
      const kind = dk === 'predefined' ? 'template' : dk;
      const from = add(kind, dn, 'tenant', {
        reason: kind === 'template' ? 'Predefined Zscaler dictionary used as a clone template.' : 'Already present in the tenant.',
        packs: [],
      });
      const to = nodes.get(`${it.kind}:${it.name}`);
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
  create: 'st-create', modify: 'st-modify', reuse: 'st-reuse', reuse_differs: 'st-differs',
  conflict: 'st-blocked', blocked_dependency: 'st-blocked', skip_empty: 'st-blocked', noop: 'st-reuse', tenant: 'st-tenant',
  created: 'st-ok', modified: 'st-ok', reused: 'st-reuse', skipped: 'st-blocked', failed: 'st-fail',
};
const DZ_FLOW_LABEL = {
  create: 'will create', modify: 'will modify', reuse: 'already present', reuse_differs: 'kept as-is (differs)',
  conflict: 'conflict', blocked_dependency: 'skipped', skip_empty: 'skipped', noop: 'no change', tenant: 'in tenant',
  created: 'created', modified: 'modified', reused: 'reused', skipped: 'skipped', failed: 'FAILED',
};

function _dzFlowHtml(items, results) {
  if (!items || !items.length) return `<div class="dz-empty">Nothing to draw.</div>`;
  const g = _dzFlowGraph(items, results);
  const G = DZ_FLOW_GEO;
  const trunc = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
  const heads = g.used.map((u, ci) => `<text class="dz-flow-head" x="${G.pad + ci * (G.w + G.gapX)}" y="${G.pad + 14}">${_dzE(DZ_FLOW_COLS[u.i].title.toUpperCase())}</text>`).join('');
  const edgeHtml = g.edges.map(e => {
    const a = g.nodes.get(e.from), b = g.nodes.get(e.to);
    const x1 = a.x + G.w, y1 = a.y + G.h / 2, x2 = b.x, y2 = b.y + G.h / 2, dx = G.gapX * 0.55;
    const st = b.result || b.status;
    const flow = (st === 'create' || st === 'modify' || st === 'created' || st === 'modified') ? ' flow' : '';
    const bad = (st === 'conflict' || st === 'blocked_dependency' || st === 'skip_empty' || st === 'skipped' || st === 'failed') ? ' bad' : '';
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
      <text class="kind" x="18" y="16">${_dzE((DZ_KIND[n.kind] || n.kind).toUpperCase())}${n.tweak ? ' · TWEAK' : ''}</text>
      <text class="st" x="${G.w - 10}" y="16" text-anchor="end">${_dzE(label)}</text>
      <text class="name" x="18" y="34">${_dzE(trunc(n.name, 27))}</text>
      <text class="pk" x="18" y="50">${_dzE(trunc(n.packs && n.packs.length ? n.packs.join(', ') : (n.kind === 'template' ? 'Zscaler predefined' : 'existing in tenant'), 36))}</text>
    </g>`;
  }).join('');
  const counts = { create: 0, modify: 0, reuse: 0, blocked: 0, tenant: 0 };
  for (const n of g.nodes.values()) {
    const st = n.result || n.status;
    if (st === 'create' || st === 'created') counts.create++;
    else if (st === 'modify' || st === 'modified') counts.modify++;
    else if (st === 'tenant') counts.tenant++;
    else if (['conflict', 'blocked_dependency', 'skip_empty', 'skipped', 'failed'].includes(st)) counts.blocked++;
    else counts.reuse++;
  }
  return `
    <div class="dz-flow">
      <div class="dz-flow-bar">
        <div class="dz-flow-legend">
          <span><i class="sw st-create"></i>${results ? 'created' : 'will create'} ${counts.create}</span>
          <span><i class="sw st-modify"></i>modify ${counts.modify}</span>
          <span><i class="sw st-reuse"></i>reuse ${counts.reuse}</span>
          <span><i class="sw st-tenant"></i>tenant ${counts.tenant}</span>
          <span><i class="sw st-blocked"></i>skipped/blocked ${counts.blocked}</span>
        </div>
        <div class="dz-flow-zoom" role="group" aria-label="Zoom">
          <button type="button" class="dz-btn quiet" onclick="_dzFlowZoom(-0.15)" aria-label="Zoom out">−</button>
          <button type="button" class="dz-btn quiet" onclick="_dzFlowZoom(0)" aria-label="Fit to width">Fit</button>
          <button type="button" class="dz-btn quiet" onclick="_dzFlowZoom(0.15)" aria-label="Zoom in">+</button>
        </div>
      </div>
      <div class="dz-flow-wrap" id="dzFlowWrap" onmouseover="_dzFlowOver(event)" onmouseout="_dzFlowOut(event)" onclick="_dzFlowClick(event)" onkeydown="_dzFlowKey(event)">
        <svg id="dzFlowSvg" viewBox="0 0 ${DZ_FLOW.W} ${DZ_FLOW.H}" width="${DZ_FLOW.W}" height="${DZ_FLOW.H}" role="img" aria-label="Dependency flow: templates to dictionaries to engines to policies">
          <g class="dz-heads">${heads}</g>
          <g class="dz-edges">${edgeHtml}</g>
          <g class="dz-nodes">${nodeHtml}</g>
        </svg>
      </div>
      <div class="dz-flow-hint">Hover a node to trace what it depends on and what depends on it. Click to pin. Names are truncated — hover for the full name and reason.</div>
    </div>`;
}

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
  if (!key) {
    svg.querySelectorAll('.is-dim, .is-hi').forEach(el => el.classList.remove('is-dim', 'is-hi'));
    return;
  }
  const { keep, edges } = _dzFlowRelated(key);
  svg.querySelectorAll('.dz-node').forEach(n => n.classList.toggle('is-dim', !keep.has(n.dataset.key)));
  for (const e of edges) {
    const on = keep.has(e.from) && keep.has(e.to);
    e.el.classList.toggle('is-hi', on); e.el.classList.toggle('is-dim', !on);
  }
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
