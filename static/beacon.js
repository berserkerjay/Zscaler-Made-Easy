// Beacon tab: what changed in the Zscaler SDK, the API and the Terraform
// provider since the last run, the tenant API watch (GET only, and only
// the endpoints in scope on the Scope page) and the history. Talks only to
// /api/beacon, /api/beacon/run, /api/beacon/scope (what the watch would
// read; no tenant call) and, for the tenant choices, /api/tenant-profiles.
(function () {
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const $ = id => document.getElementById(id);
  const WATCHER = { sdk: 'SDK', api: 'API', terraform: 'Terraform', tenant: 'Tenant' };
  const KIND = { version: 'version', changelog: 'changelog', drift_new: 'new drift', drift_cleared: 'cleared', doc_changed: 'page changed', doc_gone: 'page gone', endpoint_status: 'endpoint', scope_changed: 'scope' };
  let polling = null;

  function say(kind, html) {
    const el = $('bcStatus');
    el.hidden = false;
    el.className = `adv-status ${kind}`;
    el.innerHTML = html;
  }
  async function api(path, body) {
    const r = await fetch(path, body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : { cache: 'no-store' });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((data && data.detail) || `Error ${r.status}`);
    return data;
  }
  const when = iso => { if (!iso) return '—'; const d = new Date(iso); return isNaN(d) ? E(iso) : E(d.toLocaleString()); };
  const chip = (text, cls) => `<span class="chip ${cls || ''}">${E(text)}</span>`;
  const statusChip = w => !w ? chip('not run') : w.status === 'ok' ? chip('read', 'ok') : w.status === 'offline' ? chip('offline run') : chip(w.status, 'warn');
  function findingsTable(list, empty) {
    if (!list || !list.length) return `<p class="dim">${E(empty)}</p>`;
    return `<div class="tw"><table class="bp-table adv-table"><thead><tr><th scope="col">Level</th><th scope="col">Finding</th></tr></thead><tbody>
      ${list.map(f => `<tr><td>${chip(f.level, f.level === 'drift' ? 'bad' : '')}</td><td class="adv-sbd-ev">${E(f.text)}</td></tr>`).join('')}</tbody></table></div>`;
  }
  const reason = w => (w && w.reason ? `<p class="dim">${E(w.reason)}</p>` : '');
  function kv(rows) {
    return `<div class="tw"><table class="bp-table adv-table"><tbody>${rows.filter(r => r).map(([k, v]) => `<tr><th scope="row" class="adv-k">${E(k)}</th><td>${v}</td></tr>`).join('')}</tbody></table></div>`;
  }

  // ---- Changed since last run ----------------------------------------------
  function renderChanges(d) {
    const latest = d.latest, diff = d.diff || {};
    if (!latest) { $('bcChanges').innerHTML = '<span class="dim">Beacon has not run on this computer yet. Click Run now; the first run is the baseline the next one is compared with.</span>'; return; }
    const changes = diff.changes || [];
    const drift = latest.drift || [];
    const head = (diff.summary || [])[0] || '';
    $('bcChanges').innerHTML = `
      <div class="adv-sbd-score"><div class="n">${changes.length ? E(changes.length) : '✓'}</div><div class="g">${changes.length ? 'change' + (changes.length === 1 ? '' : 's') : 'No changes'}</div></div>
      <div class="adv-sbd-counts">${chip(`${drift.length} drift`, drift.length ? 'bad' : 'ok')} ${chip(latest.online ? 'online run' : 'offline run')} ${latest.tenant ? chip(`tenant: ${latest.tenant.label}`) : ''}
        <div style="margin-top:0.35rem;">${E(head)}</div>
        <div class="dim" style="margin-top:0.25rem;">This run: ${when(latest.at)} (${E(latest.trigger || '')}, ${E(latest.seconds)} s). Compared with: ${diff.against && diff.against.upstream_at ? when(diff.against.upstream_at) : 'nothing yet'}${diff.against && diff.against.tenant_at ? `; tenant watch compared with ${when(diff.against.tenant_at)}` : ''}.</div></div>
      ${changes.length ? `<div class="tw" style="flex-basis:100%;"><table class="bp-table adv-table" aria-label="Changes since the last run"><thead><tr><th scope="col">Area</th><th scope="col">What</th><th scope="col">Change</th></tr></thead><tbody>
        ${changes.map(c => `<tr><td>${E(WATCHER[c.watcher] || c.watcher)}</td><td>${chip(KIND[c.kind] || c.kind, c.kind === 'drift_new' ? 'bad' : c.kind === 'drift_cleared' ? 'ok' : '')}</td><td class="adv-sbd-ev">${E(c.text)}${c.url ? ` <a href="${E(c.url)}" target="_blank" rel="noopener">open</a>` : ''}</td></tr>`).join('')}
      </tbody></table></div>` : ''}`;
  }
  function renderTimer(d) {
    const t = d.timer || {};
    const parts = [];
    if (!t.enabled) parts.push(t.interval_hours === 0 ? 'The timer is off (DLP_CHECK_BEACON_HOURS=0).' : 'The timer is not running on this server.');
    else parts.push(`The timer runs the online SDK, API and Terraform watchers every ${E(t.interval_hours)} hour${t.interval_hours === 1 ? '' : 's'} while this server runs (DLP_CHECK_BEACON_HOURS); next run ${when(t.next_run_at)}.`);
    if (t.last_status === 'error' && t.last_error) parts.push(`Last run failed: ${E(t.last_error)}`);
    parts.push('It never runs the tenant API watch.');
    $('bcTimer').innerHTML = parts.join(' ');
  }

  // ---- SDK -----------------------------------------------------------------
  function renderSdk(w) {
    if (!w) return;
    const ld = w.latest_diff, pd = w.prerelease_diff;
    const diffLine = x => !x ? '' : (x.missing && x.missing.length ? `<span class="chip bad">no longer ships</span> ${E(x.missing.join(', '))}` :
      x.changed && x.changed.length ? `<span class="chip warn">changes</span> ${E(x.changed.join(', '))}` : '<span class="chip ok">changes none of the modules the app calls</span>');
    $('bcSdk').innerHTML = `<p>${statusChip(w)}</p>${reason(w)}` + kv([
      ['Installed', E(w.installed || 'not installed')],
      ['Latest release on PyPI', w.latest ? `${E(w.latest)}${w.latest_uploaded ? ` <span class="dim">(${E(String(w.latest_uploaded).slice(0, 10))})</span>` : ''}` : '<span class="dim">not read</span>'],
      ['Newest prerelease', w.prerelease ? `${E(w.prerelease)}${w.prerelease_uploaded ? ` <span class="dim">(${E(String(w.prerelease_uploaded).slice(0, 10))})</span>` : ''}` : '<span class="dim">none or not read</span>'],
      ld ? [`What ${ld.version} changes`, diffLine(ld)] : null,
      pd ? [`What ${pd.version} changes`, diffLine(pd)] : null,
      ['Changelog, newest entry', w.changelog_head ? E(w.changelog_head) : '<span class="dim">not read</span>'],
    ]) + findingsTable(w.findings, 'No SDK findings.');
  }

  // ---- API -----------------------------------------------------------------
  function renderApi(w) {
    if (!w) return;
    const sd = w.service_definition, ref = w.reference;
    let html = `<p>${statusChip(w)}</p>${reason(w)}` + kv([
      ['Service definition', sd ? `${E(sd.version)} · apiVersion ${E(sd.api_version || '?')} · ${E(sd.operations)} operations` : '<span class="dim">not read (no 2.x prerelease, or an offline run)</span>'],
      ['API reference', ref ? (ref.reachable ? '<span class="chip ok">answers</span>' : `<span class="chip warn">not fetched</span> <span class="dim">${E(ref.error || '')}</span>`) + (ref.url ? ` <a href="${E(ref.url)}" target="_blank" rel="noopener">open</a>` : '') : '<span class="dim">not read</span>'],
    ]);
    if (sd && sd.endpoints && Object.keys(sd.endpoints).length) {
      html += `<div class="tw"><table class="bp-table adv-table" aria-label="What the app writes, against the service definition"><thead><tr><th scope="col">What the app writes</th><th scope="col">Operation</th><th scope="col">Fields the definition does not list</th></tr></thead><tbody>
        ${Object.entries(sd.endpoints).map(([k, e]) => `<tr><td>${E(k)}</td><td>${e.operation ? E(e.operation) : '<span class="chip bad">none</span>'}</td><td>${(e.unknown || []).length ? E(e.unknown.join(', ')) : '<span class="dim">—</span>'}</td></tr>`).join('')}</tbody></table></div>`;
    }
    if ((w.pages || []).length) {
      html += `<div class="tw"><table class="bp-table adv-table" aria-label="Help-center and OneAPI pages"><thead><tr><th scope="col">Page</th><th scope="col">State</th></tr></thead><tbody>
        ${w.pages.map(p => `<tr><td><a href="${E(p.url)}" target="_blank" rel="noopener">${E(p.name)}</a></td><td>${p.hash ? (p.ok ? chip('read', 'ok') : chip('no readable content', 'warn')) : chip('not fetched', 'warn')} <span class="dim">${E(p.reason || '')}</span></td></tr>`).join('')}</tbody></table></div>`;
    }
    $('bcApi').innerHTML = html + findingsTable(w.findings, 'No API findings.');
  }
  function renderTenant(t, diff) {
    if (!t) { $('bcTenantBody').innerHTML = '<p class="dim">The latest run did not include a tenant API watch.</p>'; return; }
    const changed = new Set(((diff || {}).changes || []).filter(c => c.watcher === 'tenant').map(c => c.endpoint));
    const counts = Object.entries(t.counts || {}).map(([k, v]) => chip(`${v} ${k}`, k === 'OK' ? 'ok' : k === 'skipped' || k === 'not probed' ? '' : 'warn')).join(' ');
    const cls = s => s === 'OK' ? 'ok' : s === 'skipped' || s === 'not probed' ? '' : 'warn';
    const sc = t.scope;
    const out = sc ? (sc.not_in_scope || []).concat(sc.unmapped || []) : [];
    const scopeLine = sc ? `<p>Read only what is in scope: ${E(sc.summary)}${sc.source ? ` <span class="dim">(from ${E(sc.source)})</span>` : ''}.${out.length ? ` <details class="bc-out"><summary>${E(out.length)} endpoint${out.length === 1 ? '' : 's'} not in scope or unmapped, never read</summary><p class="dim mono">${E(out.join(', '))}</p></details>` : ''}</p>`
      : '<p class="dim">This watch ran before Beacon followed the Scope page: it read every endpoint the app uses.</p>';
    $('bcTenantBody').innerHTML = `${scopeLine}<p>${chip(t.label)} ${counts} <span class="dim">${E(t.requests)} GET requests in ${E(t.seconds)} s${t.stopped ? ` · stopped: ${E(t.stopped)}` : ''}</span></p>
      <div class="tw"><table class="bp-table adv-table" aria-label="Tenant endpoints and what they answered"><thead><tr><th scope="col">Endpoint</th><th scope="col">Answer</th><th scope="col">Items</th><th scope="col">Read by</th><th scope="col">Permission</th></tr></thead><tbody>
      ${(t.endpoints || []).map(e => `<tr${changed.has(e.endpoint) ? ' class="bc-changed"' : ''}><td class="mono">${E(e.endpoint)}${changed.has(e.endpoint) ? ' ' + chip('changed', 'warn') : ''}</td><td>${chip(e.status, cls(e.status))}${e.http && e.status !== 'OK' ? ` <span class="dim">HTTP ${E(e.http)}</span>` : ''}${e.error ? `<div class="dim">${E(e.error)}</div>` : ''}</td><td class="num">${e.items == null ? '' : E(e.items)}</td><td class="dim">${E((e.used_by || []).join(', '))}</td><td class="dim">${E(e.permission || '')}</td></tr>`).join('')}
      </tbody></table></div>`;
  }

  // ---- Terraform -----------------------------------------------------------
  function renderTf(w) {
    if (!w) return;
    const und = Object.entries(w.docs_undocumented || {});
    $('bcTf').innerHTML = `<p>${statusChip(w)}</p>${reason(w)}` + kv([
      ['Pinned in the workspaces', E(w.pinned || '?')],
      ['Latest on the registry', w.latest ? `${E(w.latest)}${w.published ? ` <span class="dim">(${E(String(w.published).slice(0, 10))})</span>` : ''} ${w.pin_allows_latest === true ? chip('inside the pin', 'ok') : w.pin_allows_latest === false ? chip('outside the pin', 'bad') : ''}` : '<span class="dim">not read</span>'],
      ['Provider schema', w.schema ? (w.schema.available ? chip('read', 'ok') : `<span class="dim">not read: ${E(w.schema.error || '')}</span>`) : '<span class="dim">not read</span>'],
      ['Attributes the docs do not list', und.length ? und.map(([r, a]) => `${E(r)}: ${E(a.join(', '))}`).join('<br>') : '<span class="dim">none</span>'],
      ['Changelog, newest entry', w.changelog_head ? E(w.changelog_head) : '<span class="dim">not read</span>'],
    ]) + findingsTable(w.findings, 'No Terraform findings.');
  }

  // ---- History -------------------------------------------------------------
  function renderHistory(rows) {
    $('bcHist').querySelector('tbody').innerHTML = (rows || []).map(r => `<tr><td>${when(r.at)}</td><td>${r.online ? 'online' : 'offline'}</td><td>${E(r.trigger || '')}</td><td>${E(r.tenant || '—')}${r.tenant_scope ? `<div class="dim">${E(r.tenant_scope)}</div>` : ''}</td><td class="num">${E(r.drift)}</td><td class="num">${E(r.changes)}</td><td class="adv-sbd-ev">${E(r.summary)}</td></tr>`).join('')
      || '<tr><td colspan="7" class="dim">No runs yet.</td></tr>';
  }

  function render(d) {
    const l = d.latest;
    $('rpMeta').textContent = d.running ? 'Running…' : l ? `Last run ${new Date(l.at).toLocaleString()}` : 'Not run yet';
    renderChanges(d); renderTimer(d);
    if (l) { renderSdk(l.sdk); renderApi(l.api); renderTf(l.terraform); }
    renderTenant(l && l.tenant, d.diff);
    renderHistory(d.history);
    $('bcRun').disabled = !!d.running; $('bcRunTenant').disabled = !!d.running || !scopeOk;
  }
  async function load() {
    try {
      const d = await api('/api/beacon');
      render(d);
      return d;
    } catch (e) { say('bad', `Could not read Beacon: ${E(e.message)}`); return null; }
  }
  function poll() {
    clearTimeout(polling);
    polling = setTimeout(async () => {
      const d = await load();
      if (d && d.running) poll();
      else if (d) {
        const head = ((d.diff || {}).summary || [])[0] || 'Done.';
        say(d.timer && d.timer.last_status === 'error' ? 'warn' : 'ok', `Run finished. ${E(head)}`);
      }
    }, 3000);
  }

  // ---- The tenant for the watch: the same choices as the Live DLP feed ----
  async function tenantChoices() {
    const sel = $('bcTenant');
    const fromOpener = !!(window.opener && !window.opener.closed && typeof window.opener.migrateCredBody === 'function');
    let profiles = [];
    try { const r = await fetch('/api/tenant-profiles', { cache: 'no-store' }); if (r.ok) profiles = ((await r.json()).profiles || []); } catch (e) { /* no profiles */ }
    const opts = [];
    if (fromOpener) opts.push(['opener', 'Signed in on the assessment tab']);
    profiles.forEach(p => opts.push([`profile:${p.id}`, `${p.name || p.vanity_domain || p.id}${p.has_secret === false ? ' (no remembered secret)' : ''}`]));
    opts.push(['server', 'Saved on this computer (environment or tenant_config.json)']);
    sel.innerHTML = opts.map(([v, l]) => `<option value="${E(v)}">${E(l)}</option>`).join('');
  }
  function credBody() {
    const v = $('bcTenant').value || 'server';
    if (v === 'opener' && window.opener && !window.opener.closed && typeof window.opener.migrateCredBody === 'function') return window.opener.migrateCredBody() || {};
    if (v.startsWith('profile:')) return { profile_id: v.slice(8) };
    return {};
  }

  // ---- What is in scope: the Scope page's selection -------------------------
  // The tenant API watch reads only the endpoints of the ticked scopes and
  // of the channels marked Zscaler (every GET counts against the tenant's
  // ZIA API rate limit). Read live from the assessment tab that opened this
  // one, else from the ticks the Scope page publishes on every change
  // (localStorage 'zassess_scopes_live_v1', kept in step like the channels),
  // never from the last "Save config" copy, which can be stale. Without
  // either, nothing is sent and the server uses the chosen profile's saved
  // scopes and channels (or refuses). Only each declared channel's choice is
  // sent: the Scope page's free-text notes never leave this browser.
  function readJson(key, fallback) {
    try { const raw = localStorage.getItem(key); const v = raw ? JSON.parse(raw) : fallback; return v == null ? fallback : v; } catch (e) { return fallback; }
  }
  function declared(state) {
    const out = {};
    Object.entries(state || {}).forEach(([id, v]) => {
      const choice = v && typeof v === 'object' ? v.choice : v;
      if (choice === 'zscaler' || choice === 'alternative') out[id] = choice;
    });
    return out;
  }
  function scopeSelection() {
    let scopes = null, channels = null;
    const op = window.opener && !window.opener.closed ? window.opener : null;
    try { if (op && typeof op.getSelectedScopes === 'function') scopes = op.getSelectedScopes(); } catch (e) { scopes = null; }
    try { if (op && typeof op.__dbChannelScope === 'function') channels = declared(op.__dbChannelScope()); } catch (e) { channels = null; }
    if (!Array.isArray(scopes)) {
      const live = readJson('zassess_scopes_live_v1', null);
      scopes = live && Array.isArray(live.scopes) ? live.scopes : null;
    }
    // The Scope page's ticks are unknown here: send no page selection at all,
    // so the profile's saved selection is used whole, never mixed with stray channels.
    if (!Array.isArray(scopes)) return { scopes: [], channels: {} };
    if (!channels) channels = declared(readJson('zassess_channels_v1', {}));
    return { scopes: scopes.map(String), channels };
  }
  let scopeOk = false;
  let lastAsked = null, lastShown = null;
  function showScope(html) {
    // A polite live region: rewrite it only when what it says changed.
    if (html === lastShown) return;
    lastShown = html;
    $('bcScope').innerHTML = html;
  }
  async function previewScope() {
    const sc = scopeSelection();
    const cb = credBody();
    const body = { scopes: sc.scopes, channels: sc.channels, profile_id: cb.profile_id || '' };
    const asked = JSON.stringify(body);
    // Nothing changed since the last preview (a window focus): no request, no rewrite.
    if (asked !== lastAsked) try {
      const d = await api('/api/beacon/scope', body);
      lastAsked = asked;
      scopeOk = !!d.ok;
      showScope(d.ok
        ? `The watch will read <strong>${E(d.summary)}</strong> <span class="dim">(from ${E(d.source)}; ${E((d.not_in_scope || []).length + (d.unmapped || []).length)} endpoints not in scope are never read)</span>.`
        : `<span class="chip warn">${E(d.detail)}</span>`);
    } catch (e) {
      lastAsked = null;
      scopeOk = false;
      showScope(`Could not work out what is in scope: ${E(e.message)}`);
    }
    $('bcRunTenant').disabled = !scopeOk || $('bcRun').disabled;
    return sc;
  }

  async function run(withTenant) {
    const online = $('bcOnline').checked;
    const sc = scopeSelection();
    const body = Object.assign(withTenant ? credBody() : {}, { online, tenant_watch: !!withTenant },
      withTenant ? { scopes: sc.scopes, channels: sc.channels } : {});
    $('bcRun').disabled = true; $('bcRunTenant').disabled = true;
    say('', withTenant ? 'Signing in to the tenant…' : 'Starting…');
    try {
      const d = await api('/api/beacon/run', body);
      say('', `Running${online ? ' online' : ' offline'}${d.tenant ? `, with the tenant API watch on ${E(d.tenant)}: only what is in scope, ${E(d.scope ? d.scope.summary : `${d.endpoints} endpoints`)} (GET only, about one a second)` : ''}. This page updates when it finishes.`);
      $('rpMeta').textContent = 'Running…';
      poll();
    } catch (e) {
      say('bad', `Could not start: ${E(e.message)}`);
      $('bcRun').disabled = false; $('bcRunTenant').disabled = !scopeOk;
    }
  }

  $('bcRun').addEventListener('click', () => run(false));
  $('bcRunTenant').addEventListener('click', () => run(true));
  $('bcTenant').addEventListener('change', previewScope);
  window.addEventListener('focus', previewScope);
  window.addEventListener('storage', e => { if (!e.key || e.key.startsWith('zassess_channels_v1') || e.key === 'zassess_scopes_live_v1') previewScope(); });
  tenantChoices().then(previewScope);
  load().then(d => { if (d && d.running) poll(); });
})();
