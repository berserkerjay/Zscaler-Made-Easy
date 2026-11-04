// Advanced settings tab: the policy pack library (built-in + uploaded),
// adding a pack from JSON / Terraform / ZIP, and what this server is
// configured to allow. Talks only to /api/pack-library/*.
(function () {
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const $ = id => document.getElementById(id);
  const CH = { web: 'Web DLP', endpoint: 'Endpoint DLP', saas: 'SaaS DLP', email: 'Email DLP', cloud_app: 'Cloud App Control', file_type: 'File Type Control', url: 'URL Filtering', ssl: 'SSL Inspection' };
  let chosen = [];      // { name, content, encoding }
  let preview = null;   // last /preview answer
  let status = null;    // last library answer

  function say(kind, html) {
    const el = $('advStatus');
    el.hidden = false;
    el.className = `adv-status ${kind}`;
    el.innerHTML = html;
    el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }
  function clearSay() { const el = $('advStatus'); el.hidden = true; el.innerHTML = ''; }

  // A Terraform download names the assessor in every provenance tag, as
  // Deploy policy packs does: this page's field, else the assessment tab's
  // Scope assessment name (when this tab was opened from it).
  const assessorField = $('advAssessor');
  try {
    const o = window.opener && !window.opener.closed && window.opener.document.getElementById('assessor');
    if (assessorField && o && !assessorField.value) assessorField.value = String(o.value || '').trim();
  } catch (e) { /* cross-window: the field stays as typed */ }
  document.addEventListener('click', e => {
    const a = e.target && e.target.closest ? e.target.closest('a[href*="/terraform.zip"]') : null;
    if (!a) return;
    const u = new URL(a.getAttribute('href'), location.href);
    const who = advAssessorName();
    if (!who) {
      // Every object in the workspace names the assessor, never Zscaler Made Easy: no name, no download.
      e.preventDefault();
      const f = document.getElementById('advAssessor');
      alert("Enter the assessor's name first: every object the pack creates names the assessor in its description.");
      if (f) f.focus();
      return;
    }
    if (/dlp[\W_]*check|zscaler[\W_]*made[\W_]*easy/i.test(who)) {
      // The tool's own name, in any spelling, is refused here as on the server (pack_deploy.TOOL_NAME_PATTERN).
      e.preventDefault();
      alert("Name the person who assesses and deploys the pack, not the tool (no \"Zscaler Made Easy\").");
      const f = document.getElementById('advAssessor');
      if (f) f.focus();
      return;
    }
    u.searchParams.set('assessor', who);
    a.setAttribute('href', u.pathname + u.search);
  }, true);

  async function api(path, body) {
    const r = await fetch(path, body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : { cache: 'no-store' });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((data && data.detail) || `Error ${r.status}`);
    return data;
  }

  // Packs deploy detection only; containment channels are managed
  // separately and never annotated as part of a pack (kept in step with
  // pack_channels.CARVED_CHANNELS).
  const CARVED = ['cloud_app', 'file_type', 'url', 'ssl'];
  function channels(c) {
    const keys = c && typeof c === 'object' && !Array.isArray(c) ? Object.keys(c) : (c || []);
    const dlp = keys.filter(k => !CARVED.includes(k));
    const carved = keys.filter(k => CARVED.includes(k));
    const chips = dlp.map(k => `<span class="chip">${E(CH[k] || k)}</span>`).join(' ');
    const note = carved.length ? `<span class="chip carved" title="Detection only. ${carved.map(k => E(CH[k] || k)).join(', ')} are managed separately, not by this pack.">${carved.map(k => E(CH[k] || k)).join(' · ')} carved out</span>` : '';
    return (chips + (chips && note ? ' ' : '') + note) || '<span class="dim">none</span>';
  }

  function renderLibrary(lib) {
    status = lib;
    const packs = lib.packs || [];
    const tb = $('advPacks').querySelector('tbody');
    if (!packs.length) { tb.innerHTML = '<tr><td colspan="7" class="dim">No packs found.</td></tr>'; }
    else {
      tb.innerHTML = packs.map(p => `
        <tr>
          <th scope="row"><div class="adv-pname">${E(p.name || p.id)}</div><div class="dim mono">${E(p.id)}${p.version ? ' · v' + E(p.version) : ''}</div>${p.description ? `<div class="adv-pdesc">${E(String(p.description).slice(0, 220))}${String(p.description).length > 220 ? '…' : ''}</div>` : ''}</th>
          <td>${p.source === 'uploaded' ? '<span class="chip ok">Uploaded</span>' : '<span class="chip">Built-in</span>'}${p.uploaded_at ? `<div class="dim">${E(String(p.uploaded_at).replace('T', ' ').replace('Z', ' UTC'))}</div>` : ''}</td>
          <td class="num">${p.dictionaries || 0}</td><td class="num">${p.engines || 0}</td><td class="num">${p.policies || 0}</td>
          <td>${channels(p.channels)}</td>
          <td class="adv-acts"><a class="rp-btn" href="/api/pack-library/${encodeURIComponent(p.id)}/bundle" title="Download this pack as one JSON file">JSON</a><a class="rp-btn" href="/api/pack-library/${encodeURIComponent(p.id)}/terraform.zip" title="Download this pack as a Terraform workspace for the zscaler/zia provider (static mode)">Terraform</a>${p.source === 'uploaded' ? `<button type="button" class="rp-btn danger" data-remove="${E(p.id)}" title="Remove this uploaded pack from the library">Remove</button>` : ''}</td>
        </tr>`).join('');
    }
    const up = packs.filter(p => p.source === 'uploaded').length;
    $('rpMeta').textContent = `${packs.length} pack${packs.length === 1 ? '' : 's'} · ${up} uploaded · ${lib.writes_allowed ? 'uploads enabled' : 'uploads locked'}`;
    tb.querySelectorAll('[data-remove]').forEach(b => b.addEventListener('click', () => removePack(b.dataset.remove)));
    renderServer(lib);
    const locked = !lib.writes_allowed;
    $('advAdd').disabled = locked || !(preview && preview.ok);
    if (locked) say('warn', `<strong>Uploads are locked on this server.</strong> Adding or removing packs is allowed when the server only answers this machine (bind host 127.0.0.1) or when the UI token is on (<code>ZSCALER_UI_AUTH=1</code>). This server binds <code>${E(lib.bind_host)}</code> and the token gate is ${lib.ui_auth ? 'on' : 'off'}. You can still check files and download packs.`);
  }

  function renderServer(lib) {
    const rows = [
      ['Library folder (uploaded packs)', `<code>${E(lib.user_packs_dir)}</code><div class="dim">Change it with <code>DLP_CHECK_USER_PACKS</code>. In the container it is the <code>/data</code> volume, so packs survive image updates.</div>`],
      ['Built-in packs folder', `<code>${E(lib.packs_root)}</code>`],
      ['Adding and removing packs', lib.writes_allowed ? '<span class="chip ok">Allowed</span>' : '<span class="chip warn">Locked</span> <span class="dim">bind to 127.0.0.1 or set ZSCALER_UI_AUTH=1</span>'],
      ['Bind host', `<code>${E(lib.bind_host)}</code> <span class="dim">(ZSCALER_BIND_HOST${lib.env && lib.env.ZSCALER_BIND_HOST ? ' = ' + E(lib.env.ZSCALER_BIND_HOST) : ' not set'})</span>`],
      ['UI token gate', lib.ui_auth ? '<span class="chip ok">On</span> <span class="dim">every browser needs the token from ui_token.txt</span>' : '<span class="chip warn">Off</span> <span class="dim">anyone who can reach this address can use the app (ZSCALER_UI_AUTH=0); remove that setting, or set ZSCALER_UI_AUTH=1, and restart to turn it back on</span>'],
      ['Changes to the Zscaler tenant', lib.writes_to_tenant ? '<span class="chip warn">Enabled</span> <span class="dim">Deploy policy packs and remediation can write, after your approval</span>' : '<span class="chip ok">Read-only</span> <span class="dim">the app only reads the tenant; set ZSCALER_WRITES=1 to allow deployments</span>'],
      ['Upload limit', `${E(lib.max_upload_mb)} MB per upload`],
    ];
    $('advServer').querySelector('tbody').innerHTML = rows.map(([k, v]) => `<tr><th scope="row" class="adv-k">${E(k)}</th><td>${v}</td></tr>`).join('');
  }

  async function loadLibrary() {
    try { renderLibrary(await api('/api/pack-library')); }
    catch (e) { say('bad', `<strong>Could not read the library.</strong> ${E(e.message)}`); }
  }

  // ---- files ---------------------------------------------------------------
  function readFile(f) {
    return new Promise((resolve, reject) => {
      const zip = /\.zip$/i.test(f.name) || f.type === 'application/zip' || f.type === 'application/x-zip-compressed';
      const r = new FileReader();
      r.onerror = () => reject(new Error(`Could not read ${f.name}`));
      if (zip) { r.onload = () => resolve({ name: f.name, content: String(r.result).split(',')[1] || '', encoding: 'base64' }); r.readAsDataURL(f); }
      else { r.onload = () => resolve({ name: f.name, content: String(r.result) }); r.readAsText(f); }
    });
  }
  async function takeFiles(list) {
    const files = Array.from(list || []).filter(f => /\.(json|tf|zip)$/i.test(f.name));
    if (!files.length) { say('warn', 'Choose JSON, Terraform (.tf) or ZIP files.'); return; }
    try { chosen = await Promise.all(files.map(readFile)); }
    catch (e) { say('bad', E(e.message)); return; }
    preview = null; $('advAdd').disabled = true; $('advPreview').hidden = true;
    $('advFileList').innerHTML = chosen.map(f => `<li><span class="mono">${E(f.name)}</span> <span class="dim">${f.encoding === 'base64' ? 'zip' : (/\.tf$/i.test(f.name) ? 'terraform' : 'json')}</span></li>`).join('');
    clearSay();
    checkFiles();
  }

  function payload() {
    return { files: chosen, pack_name: $('advName').value.trim(), pack_id: $('advId').value.trim(), description: $('advDesc').value.trim() };
  }

  async function checkFiles() {
    if (!chosen.length) { say('warn', 'Choose the files first.'); return; }
    $('advCheck').disabled = true;
    try {
      preview = await api('/api/pack-library/preview', payload());
      renderPreview(preview);
    } catch (e) { preview = null; say('bad', `<strong>Check failed.</strong> ${E(e.message)}`); }
    $('advCheck').disabled = false;
    $('advAdd').disabled = !(preview && preview.ok && status && status.writes_allowed);
  }

  function renderPreview(v) {
    const box = $('advPreview');
    box.hidden = false;
    const c = v.counts || {};
    const list = (items, f) => items && items.length ? `<ul class="adv-list">${items.map(f).join('')}</ul>` : '<span class="dim">none</span>';
    box.innerHTML = `
      <div class="adv-verdict ${v.ok ? 'ok' : 'bad'}">${v.ok ? '✓ Ready to add' : '✕ Not ready'}<span class="dim"> · ${E(v.name || '')}${v.pack_id ? ' · id ' + E(v.pack_id) : ''}${v.format ? ' · ' + E(v.format) : ''}</span></div>
      ${v.problems && v.problems.length ? `<div class="bp-card risk"><div class="t">Fix these before adding</div><ul class="adv-list">${v.problems.map(p => `<li>${E(p)}</li>`).join('')}</ul></div>` : ''}
      ${v.warnings && v.warnings.length ? `<div class="bp-card warn"><div class="t">Worth knowing (does not block)</div><ul class="adv-list">${v.warnings.map(p => `<li>${E(p)}</li>`).join('')}</ul></div>` : ''}
      <div class="df-stats">
        <div class="df-stat"><div class="n">${E(String(c.dictionaries || 0))}</div><div class="l">dictionaries${c.clones ? ` (${E(String(c.clones))} clone predefined)` : ''}</div></div>
        <div class="df-stat"><div class="n">${E(String(c.engines || 0))}</div><div class="l">engines</div></div>
        <div class="df-stat"><div class="n">${E(String(c.policies || 0))}</div><div class="l">rules</div></div>
        <div class="df-stat"><div class="n">${(v.channels || []).length}</div><div class="l">channels: ${E((v.channels || []).map(k => CH[k] || k).join(', ') || 'none')}</div></div>
      </div>
      <details class="adv-details"><summary>Dictionaries (${(v.dictionaries || []).length})</summary>${list(v.dictionaries, d => `<li><strong>${E(d.name)}</strong> <span class="dim">${d.clone ? 'clone of ' + E(d.template || 'predefined') : `${E(String(d.patterns))} pattern${d.patterns === 1 ? '' : 's'}, ${E(String(d.phrases))} phrase${d.phrases === 1 ? '' : 's'}`}${d.proximity ? ', proximity ' + E(String(d.proximity)) : ''}</span></li>`)}</details>
      <details class="adv-details"><summary>Engines (${(v.engines || []).length})</summary>${list(v.engines, e => `<li><strong>${E(e.name)}</strong> <code class="adv-expr">${E(e.expression)}</code></li>`)}</details>
      <details class="adv-details"><summary>Rules (${(v.policies || []).length})</summary>${list(v.policies, p => `<li><strong>${E(p.name)}</strong> <span class="chip">${E(CH[p.channel] || p.channel)}</span> <span class="dim">${E(p.action || '')} · ${E(p.state || '')}${p.engines && p.engines.length ? ' · ' + E(p.engines.join(', ')) : ''}${p.sub_rules ? ` · ${E(String(p.sub_rules))} sub-rule${p.sub_rules === 1 ? '' : 's'}` : ''}</span></li>`)}</details>`;
  }

  async function addPack() {
    if (!preview || !preview.ok) return;
    $('advAdd').disabled = true;
    try {
      const r = await api('/api/pack-library/upload', payload());
      const p = r.pack || {};
      const tf = r.terraform || {};
      const tfHtml = tf.ok
        ? `<div style="margin-top:0.5rem;"><strong>Transcribed to Terraform.</strong> ${tf.resources} resource${tf.resources === 1 ? '' : 's'} and ${tf.data_sources} data source${tf.data_sources === 1 ? '' : 's'} in ${(tf.files || []).length} files (${(tf.files || []).map(E).join(', ')}), saved beside the pack in <code>${E(tf.dir)}</code>. Same policy, vendor-neutral and reviewable in a pull request. <a class="rp-btn" href="${E(tf.download)}" style="margin-left:0.4rem;">⬇ Export Terraform</a></div>`
        : `<div style="margin-top:0.5rem;color:var(--warn);"><strong>Added, but the Terraform transcription failed:</strong> ${E(tf.error || 'unknown error')}. The pack is usable; use the Terraform button in the library once the cause is fixed.</div>`;
      say('ok', `<strong>Added “${E(p.name || p.id)}”.</strong> It is now offered in Deploy policy packs, the Data flow map and the Terraform hand-off. Rules are created DISABLED and monitor-only when deployed, so nothing changes in the tenant until you review and enable them.${r.validation && r.validation.native ? ' The upload was a native Zscaler export: ids became names and tenant-specific scope was dropped (see the warnings above).' : ''}${tfHtml}`);
      chosen = []; preview = null; $('advFiles').value = ''; $('advFileList').innerHTML = ''; $('advPreview').hidden = true;
      $('advName').value = ''; $('advId').value = ''; $('advDesc').value = '';
      await loadLibrary();
    } catch (e) { say('bad', `<strong>Not added.</strong> ${E(e.message)}`); $('advAdd').disabled = false; }
  }

  async function removePack(id) {
    if (!confirm(`Remove the uploaded pack "${id}" from the library? Nothing is changed in the Zscaler tenant.`)) return;
    try { await api(`/api/pack-library/${encodeURIComponent(id)}/remove`, {}); say('ok', `<strong>Removed “${E(id)}”.</strong>`); await loadLibrary(); }
    catch (e) { say('bad', `<strong>Not removed.</strong> ${E(e.message)}`); }
  }

  // ---- app update -----------------------------------------------------------
  function updBox(html) { $('advUpdBox').innerHTML = html; }
  function renderUpdateStatus(st) {
    const btn = $('advUpdBtn');
    const here = st.local_commit ? `build <code>${E(st.local_commit)}</code>${st.branch ? ' on ' + E(st.branch) : ''}` : 'build unknown';
    if (!st.can_update) {
      updBox(`<span class="warn">${E(st.reason || 'This install cannot update itself.')}</span><div class="dim">Installed at <code>${E(st.app_dir || '')}</code></div>`);
      btn.hidden = true; return;
    }
    if (st.update_available) {
      updBox(`<strong>Update available.</strong> This install is ${here}; GitHub is on <code>${E(st.remote_commit || '?')}</code>.`);
      btn.hidden = false; btn.textContent = 'Update now';
    } else if (st.remote_commit) {
      updBox(`<span class="ok">Up to date</span> — ${here}.`);
      btn.hidden = false; btn.textContent = 'Update anyway';
    } else {
      updBox(`This install is ${here}. Could not reach GitHub to compare${st.remote_error ? `: ${E(st.remote_error)}` : ''}.`);
      btn.hidden = false; btn.textContent = 'Update now';
    }
  }
  async function checkUpdate() {
    updBox('<span class="dim">Checking GitHub…</span>');
    try { renderUpdateStatus(await api('/api/app/update/status?refresh=1')); }
    catch (e) { updBox(`<span class="warn">Could not check: ${E(e.message)}</span>`); }
  }
  async function runUpdate() {
    // The update changes this app's own code: say what happens and ask first (WCAG 3.3.4).
    if (!window.confirm('Update Zscaler Made Easy now? The app fetches and pulls the latest code from GitHub for its branch, keeps any local edits in git stash, installs the locked requirements and then asks you to restart it. Nothing in the tenant changes.')) return;
    const btn = $('advUpdBtn'), steps = $('advUpdSteps');
    btn.disabled = true; btn.textContent = 'Updating…'; steps.hidden = false;
    const lines = [];
    const show = extra => steps.innerHTML = lines.map(l => `<div class="adv-upd-line ${l.ok === false ? (l.soft ? 'soft' : 'bad') : l.ok ? 'ok' : ''}">${l.ok === false ? (l.soft ? '⚠' : '✕') : l.ok ? '✓' : '…'} ${E(l.name)}${l.detail ? ` <span class="dim">— ${E(l.detail)}</span>` : ''}</div>`).join('') + (extra || '');
    lines.push({ name: 'Pulling the latest code from GitHub', ok: null }); show();
    let res;
    try {
      const r = await fetch('/api/app/update', { method: 'POST' });
      res = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(res.detail || `HTTP ${r.status}`);
    } catch (e) { lines.length = 0; lines.push({ name: 'Update failed', ok: false, detail: e.message }); show(); btn.disabled = false; btn.textContent = 'Update now'; return; }
    lines.length = 0;
    for (const s of res.steps || []) lines.push({ name: s.name, ok: s.ok, detail: s.detail, soft: !!s.soft });
    if (!res.ok) { show(); btn.disabled = false; btn.textContent = 'Update now'; return; }
    if (!res.updated) { show('<div class="adv-upd-line ok">Already on the latest build.</div>'); btn.disabled = false; btn.textContent = 'Update anyway'; checkUpdate(); return; }
    lines.push({ name: `Restarting the app on build ${res.after}`, ok: null }); show();
    try {
      const r = await fetch('/api/app/restart', { method: 'POST' });
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
    } catch (e) { lines[lines.length - 1] = { name: 'Restart could not be scheduled', ok: false, detail: e.message + '. Close the app with STOP_Zscaler_Made_Easy.bat and open it again.' }; show(); return; }
    const started = Date.now();
    const poll = async () => {
      try {
        const h = await (await fetch('/api/health', { cache: 'no-store' })).json();
        if (h.git_commit && h.git_commit === res.after) { lines[lines.length - 1] = { name: `Restarted on build ${h.git_commit}. Reloading…`, ok: true }; show(); setTimeout(() => location.reload(), 800); return; }
      } catch (e) { /* server still restarting */ }
      if (Date.now() - started > 90000) { lines[lines.length - 1] = { name: 'The app is taking a while to come back', ok: false, soft: true, detail: 'Reload this tab in a moment.' }; show(); return; }
      setTimeout(poll, 1500);
    };
    setTimeout(poll, 2000);
  }

  // ---- CISA Secure by Design score -----------------------------------------
  const SBD_CHIP = { pass: ['ok', 'Met'], warn: ['warn', 'Partly'], fail: ['bad', 'Not met'], 'n/a': ['', 'Not scored'] };
  function renderSbd(d) {
    const c = d.counts || {};
    $('advSbdBox').innerHTML = `
      <div class="adv-sbd-score"><div class="n">${E(d.score)}<span class="pct">/100</span></div><div class="g">Grade ${E(d.grade)}</div></div>
      <div class="adv-sbd-counts"><span class="chip ok">${E(c.pass || 0)} met</span> <span class="chip warn">${E(c.warn || 0)} partly</span> <span class="chip bad">${E(c.fail || 0)} not met</span> <span class="chip">${E(c['n/a'] || 0)} not scored</span>
        <div class="dim" style="margin-top:0.35rem;">${E(d.note || '')}</div></div>`;
    const tb = $('advSbd').querySelector('tbody');
    const groups = d.principles || [];
    tb.innerHTML = groups.map(p => {
      const rows = (d.checks || []).filter(x => x.principle === p);
      if (!rows.length) return '';
      return `<tr class="adv-sbd-group"><th scope="rowgroup" colspan="4">${E(p)}</th></tr>` + rows.map(x => {
        const [cls, label] = SBD_CHIP[x.status] || ['', x.status];
        return `<tr>
          <th scope="row">${E(x.control)}<div class="dim">${E(x.pledge)}</div></th>
          <td><span class="chip ${cls}">${E(label)}</span></td>
          <td class="adv-sbd-ev">${E(x.evidence)}</td>
          <td class="adv-sbd-ev">${E(x.do)}</td>
        </tr>`;
      }).join('');
    }).join('') || '<tr><td colspan="4" class="dim">No controls reported.</td></tr>';
  }
  async function loadSbd() {
    $('advSbdBox').innerHTML = '<span class="dim">Measuring…</span>';
    try { renderSbd(await api('/api/secure-by-design')); }
    catch (e) { $('advSbdBox').innerHTML = `<span class="warn">Could not measure: ${E(e.message)}</span>`; }
  }
  $('advSbdCheck').addEventListener('click', loadSbd);
  loadSbd();

  // ---- Daily upstream contract check (the offline half, run here) ----------
  function renderUp(d) {
    const nD = (d.drift || []).length, nN = (d.notes || []).length;
    $('advUpBox').innerHTML = `
      <div class="adv-sbd-score"><div class="n">${nD ? E(nD) : '✓'}<span class="pct">${nD ? ' drift' : ''}</span></div><div class="g">${nD ? 'Act on these' : 'No drift'}</div></div>
      <div class="adv-sbd-counts"><span class="chip ${nD ? 'bad' : 'ok'}">${E(nD)} drift</span> <span class="chip">${E(nN)} note${nN === 1 ? '' : 's'}</span> <span class="chip">SDK ${E(d.sdk_installed || '?')}</span> <span class="chip">provider ${E(d.terraform_pinned || '?')}</span>
        <div class="dim" style="margin-top:0.35rem;">Offline check run on this server ${d.cached_seconds ? `${Math.round(d.cached_seconds / 60)} min ago` : 'just now'} (${E(d.generated || '')}); endpoints covered: ${E((d.endpoints_checked || []).join(', ') || '—')}.</div>
        <div class="dim" style="margin-top:0.25rem;">The daily online run: ${E((d.daily || {}).where || '')}, ${E((d.daily || {}).schedule || '')}. ${E((d.daily || {}).result || '')}</div></div>`;
    const rows = [...(d.drift || []), ...(d.notes || [])];
    $('advUp').querySelector('tbody').innerHTML = rows.map(f => `<tr><td><span class="chip ${f.level === 'drift' ? 'bad' : ''}">${E(f.level)}</span></td><td>${E(f.area)}</td><td class="adv-sbd-ev">${E(f.text)}</td></tr>`).join('')
      || '<tr><td colspan="3" class="dim">Every payload field the app sends is known to the installed SDK, and the committed Terraform parses. Nothing to act on.</td></tr>';
  }
  async function loadUp(refresh) {
    $('advUpBox').innerHTML = '<span class="dim">Checking…</span>';
    try { renderUp(await api(`/api/upstream-check${refresh ? '?refresh=1' : ''}`)); }
    catch (e) { $('advUpBox').innerHTML = `<span class="warn">Could not run the check: ${E(e.message)}</span>`; }
  }
  $('advUpCheck').addEventListener('click', () => loadUp(true));
  loadUp(false);

  // ---- Microsoft 365 endpoint list (app service groups) ---------------------
  // Off by default; fetching contacts endpoints.office.com only after the
  // switch is on and then only through this server (m365_endpoints.py).
  async function m365(method, path, body) {
    const opt = { method, cache: 'no-store' };
    if (body) { opt.headers = { 'Content-Type': 'application/json' }; opt.body = JSON.stringify(body); }
    const r = await fetch(path, opt);
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((data && data.detail) || `Error ${r.status}`);
    return data;
  }
  const day = iso => String(iso || '').slice(0, 10) || 'an unknown date';
  function renderM365(st, said) {
    const box = $('advM365Box');
    const c = st.counts || {};
    const rows = [];
    if (!st.present && st.bundled) {
      const b = st.bundled, bc = b.counts || {};
      rows.push(`<strong>No list is kept.</strong> Using the excerpt that comes with the app: Microsoft's list version ${E(b.version)} from ${E(b.date)}, checked against it ${E(b.checked)} (${E(b.age_days)} days ago): `
        + `${E(bc.sets || 0)} endpoint sets, ${E(bc.urls || 0)} host names, ${E(bc.ipv4 || 0)} IPv4 and ${E(bc.ipv6 || 0)} IPv6 ranges. `
        + (b.stale ? '<span class="warn">It is too old to use: rules on Microsoft 365 app service groups show as unknown until you fetch or import the list.</span>'
                   : 'It can show a match, never a no match. Fetch or import Microsoft\'s whole list to settle more.'));
    } else if (!st.present) {
      rows.push('<strong>No list is kept.</strong> Rules on Microsoft 365 app service groups show as unknown.');
    } else {
      const from = st.source === 'imported' ? `imported ${E(day(st.fetched_at))}` : `fetched ${E(day(st.fetched_at))}`;
      rows.push(`<strong>Version ${E(st.version || 'not stated')}</strong>, ${from}${st.checked_at && st.checked_at !== st.fetched_at ? `, last confirmed ${E(day(st.checked_at))}` : ''}: `
        + `${E(c.sets || 0)} endpoint sets, ${E(c.urls || 0)} host names, ${E(c.ipv4 || 0)} IPv4 and ${E(c.ipv6 || 0)} IPv6 ranges.`);
      rows.push(st.stale ? `<span class="warn">Stale: last confirmed ${E(st.age_days)} days ago, more than ${E(st.max_age_days)}. It settles nothing until it is refreshed or imported again.</span>`
                         : '<span class="chip ok">In use</span>');
    }
    rows.push(`Fetching from <code>${E(st.host)}</code>: ${st.enabled ? '<span class="chip warn">On</span>' : '<span class="chip ok">Off</span>'}`
      + (st.last_error ? ` <span class="warn">Last try failed: ${E(st.last_error)}</span>` : ''));
    if (said) rows.push(`<span>${E(said)}</span>`);
    box.innerHTML = rows.map(r => `<div>${r}</div>`).join('');
    $('advM365On').checked = !!st.enabled;
    $('advM365Fetch').disabled = !st.enabled;
    $('advM365Remove').disabled = !st.present;
  }
  async function loadM365(said) {
    try { renderM365(await m365('GET', '/api/m365-endpoints'), said); }
    catch (e) { $('advM365Box').innerHTML = `<span class="warn">Could not read the setting: ${E(e.message)}</span>`; }
  }
  $('advM365On').addEventListener('change', async e => {
    try { renderM365(await m365('PUT', '/api/m365-endpoints/settings', { enabled: e.target.checked }),
                     e.target.checked ? 'Fetching is on. Click Fetch now, or the app checks when you next analyze.' : 'Fetching is off. A list already kept is still used.'); }
    catch (err) { e.target.checked = !e.target.checked; loadM365(`Not changed: ${err.message}`); }
  });
  $('advM365Fetch').addEventListener('click', async () => {
    $('advM365Fetch').disabled = true;
    $('advM365Box').insertAdjacentHTML('beforeend', '<div class="dim">Fetching from endpoints.office.com…</div>');
    try { renderM365(await m365('POST', '/api/m365-endpoints/refresh'), 'Fetched: the list is current.'); }
    catch (e) { loadM365(e.message); }
  });
  $('advM365Import').addEventListener('click', () => {
    const f = ($('advM365File').files || [])[0];
    if (!f) { loadM365('Choose the file first: the JSON Microsoft\'s address answers.'); $('advM365File').focus(); return; }
    if (f.size > 2 * 1024 * 1024) { loadM365('That file is larger than 2 MB, so it is not Microsoft\'s list (about 100 KB).'); return; }
    const r = new FileReader();
    r.onload = async () => {
      try { renderM365(await m365('POST', '/api/m365-endpoints/import', { content: String(r.result || ''), version: $('advM365Ver').value.trim() }), 'Imported.'); }
      catch (e) { loadM365(e.message); }
    };
    r.onerror = () => loadM365('The file could not be read.');
    r.readAsText(f);
  });
  $('advM365Remove').addEventListener('click', async () => {
    const ok = window.dlpDialog ? await window.dlpDialog.ask({ title: 'Remove the Microsoft 365 endpoint list?', body: 'Rules on Microsoft 365 app service groups will show as unknown again until you fetch or import the list.', okLabel: 'Remove', tone: 'bad' })
                                : window.confirm('Remove the Microsoft 365 endpoint list?');
    if (!ok) return;
    try { renderM365(await m365('DELETE', '/api/m365-endpoints'), 'Removed.'); }
    catch (e) { loadM365(e.message); }
  });
  loadM365();

  // ---- Other providers' endpoint lists (vendor_endpoints.py) ----------------
  // Zoom, Webex, RingCentral, GoTo and Talkdesk app service groups. Fetching
  // is for Zoom and GoTo, each off by default, and only on Fetch now; every
  // provider can be imported from a text file; with none kept, the bundled
  // dated excerpt is shown. Built with textContent only.
  let vend = null;
  const MAX_VEND_KB = 1024;
  const VEND_FETCH = [['zoom', 'advVendZoomOn', 'advVendFetch', 'Zoom', 'assets.zoom.us'],
                      ['goto', 'advVendGotoOn', 'advVendGotoFetch', 'GoTo', 'goto-ipblocks.live.gtc.goto.com']];
  function vendLine(box, text, cls) {
    const d = document.createElement('div');
    if (cls) d.className = cls;
    d.textContent = text;
    box.appendChild(d);
    return d;
  }
  function renderVend(st, said) {
    vend = st;
    const box = $('advVendBox');
    box.textContent = '';
    (st.providers || []).forEach(p => {
      const row = document.createElement('div');
      const name = document.createElement('strong');
      name.textContent = `${p.label}: `;
      row.appendChild(name);
      const c = p.counts || {};
      const b = p.bundled || null, bc = (b && b.counts) || {};
      let text;
      if (!p.present && b) text = `no list kept. Using the excerpt that comes with the app, from ${b.date}, checked against its source ${b.checked} (${b.age_days} days ago): `
        + `${bc.ipv4 || 0} IPv4 and ${bc.ipv6 || 0} IPv6 ranges, ${bc.hosts || 0} host names, from ${b.source_name}. `
        + (b.stale ? `It is too old to use, so its app service group (${(p.names || []).join(', ')}) shows as unknown until you fetch or import the list.`
                   : 'It can show a match, never a no match.');
      else if (!p.present) text = `no list kept, so its app service group (${(p.names || []).join(', ')}) shows as unknown.`;
      else text = `${p.describe || 'a list is kept'}: ${c.ipv4 || 0} IPv4 and ${c.ipv6 || 0} IPv6 ranges, ${c.hosts || 0} host names. `
        + (p.stale ? `Stale: last confirmed ${p.age_days} days ago, more than ${st.max_age_days}; it settles nothing until it is fetched or imported again.` : 'In use.');
      row.appendChild(document.createTextNode(text));
      if (p.fetchable) row.appendChild(document.createTextNode(` Fetching from ${p.host}: ${p.enabled ? 'on' : 'off'}.`));
      else row.appendChild(document.createTextNode(' Import only.'));
      if (p.last_error) { const w = document.createElement('span'); w.className = 'warn'; w.textContent = ` Last try failed: ${p.last_error}`; row.appendChild(w); }
      box.appendChild(row);
    });
    if (st.zscaler_groups) vendLine(box, st.zscaler_groups, 'dim');
    if (said) vendLine(box, said);
    VEND_FETCH.forEach(([pid, on, go]) => {
      const pr = (st.providers || []).find(p => p.id === pid) || {};
      $(on).checked = !!pr.enabled;
      $(go).disabled = !pr.enabled;
    });
    const pick = (st.providers || []).find(p => p.id === $('advVendProv').value) || {};
    $('advVendRemove').disabled = !pick.present;
  }
  async function loadVend(said) {
    try { renderVend(await m365('GET', '/api/vendor-endpoints'), said); }
    catch (e) { const box = $('advVendBox'); box.textContent = ''; vendLine(box, `Could not read the setting: ${e.message}`, 'warn'); }
  }
  // One switch and one Fetch now button per provider that publishes a file.
  // Turning a switch on fetches nothing; only the button does.
  VEND_FETCH.forEach(([pid, on, go, label, host]) => {
    $(on).addEventListener('change', async e => {
      try { renderVend(await m365('PUT', '/api/vendor-endpoints/settings', { provider: pid, enabled: e.target.checked }),
                       e.target.checked ? `Fetching ${label}'s list is on. Nothing is fetched until you click Fetch ${label}'s list now.` : `Fetching ${label}'s list is off. A list already kept is still used.`); }
      catch (err) { e.target.checked = !e.target.checked; loadVend(`Not changed: ${err.message}`); }
    });
    $(go).addEventListener('click', async () => {
      $(go).disabled = true;
      vendLine($('advVendBox'), `Fetching from ${host}…`, 'dim');
      try { renderVend(await m365('POST', '/api/vendor-endpoints/refresh', { provider: pid }), `Fetched: ${label}'s list is current.`); }
      catch (e) { loadVend(e.message); }
    });
  });
  $('advVendProv').addEventListener('change', () => { if (vend) renderVend(vend); });
  $('advVendImport').addEventListener('click', () => {
    const f = ($('advVendFile').files || [])[0], prov = $('advVendProv').value;
    if (!f) { loadVend('Choose the text file first: one address range or host name per line.'); $('advVendFile').focus(); return; }
    if (f.size > MAX_VEND_KB * 1024) { loadVend(`That file is larger than ${MAX_VEND_KB} KB, so it is not a provider's list (a few KB).`); return; }
    const r = new FileReader();
    r.onload = async () => {
      try { renderVend(await m365('POST', '/api/vendor-endpoints/import', { provider: prov, content: String(r.result || '') }), 'Imported.'); }
      catch (e) { loadVend(e.message); }
    };
    r.onerror = () => loadVend('The file could not be read.');
    r.readAsText(f);
  });
  $('advVendRemove').addEventListener('click', async () => {
    const sel = $('advVendProv'), label = sel.options[sel.selectedIndex].textContent;
    const ok = window.dlpDialog ? await window.dlpDialog.ask({ title: `Remove ${label}'s list?`, body: `Rules on ${label}'s app service group will show as unknown again until you import or fetch the list.`, okLabel: 'Remove', tone: 'bad' })
                                : window.confirm(`Remove ${label}'s list?`);
    if (!ok) return;
    try { renderVend(await m365('DELETE', `/api/vendor-endpoints/${encodeURIComponent(sel.value)}`), 'Removed.'); }
    catch (e) { loadVend(e.message); }
  });
  loadVend();

  // ---- wiring ---------------------------------------------------------------
  $('advUpdCheck').addEventListener('click', checkUpdate);
  $('advUpdBtn').addEventListener('click', runUpdate);
  checkUpdate();
  $('advFiles').addEventListener('change', e => takeFiles(e.target.files));
  const drop = $('advDrop');
  ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', e => takeFiles(e.dataTransfer.files));
  drop.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('advFiles').click(); } });
  $('advCheck').addEventListener('click', checkFiles);
  $('advAdd').addEventListener('click', addPack);
  ['advName', 'advId', 'advDesc'].forEach(id => $(id).addEventListener('input', () => { if (preview) { preview = null; $('advAdd').disabled = true; } }));
  $('advRefresh').addEventListener('click', e => { e.preventDefault(); loadLibrary(); });
  loadLibrary();
})();


// The assessor a Terraform download names (Advanced settings' field).
function advAssessorName() {
  return String((document.getElementById('advAssessor') || {}).value || '').trim();
}

// Terraform workspace for one pack, static mode: no tenant read, no
// credentials, no import blocks — the pack transcribed as HCL.
async function advTerraform(id) {
  try {
    const r = await fetch('/api/dlp-packs/terraform', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pack_ids: [id], mode: 'static', client_id: '', client_secret: '', vanity_domain: '', assessor: advAssessorName() }) });
    if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.detail || `HTTP ${r.status}`); }
    const blob = await r.blob();
    const m = /filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') || '');
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = m ? m[1] : `${id}-terraform.zip`;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  } catch (e) { alert(`Terraform export failed: ${e.message}`); }
}
window.advTerraform = advTerraform;
