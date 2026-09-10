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

  async function api(path, body) {
    const r = await fetch(path, body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : { cache: 'no-store' });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((data && data.detail) || `Error ${r.status}`);
    return data;
  }

  function channels(c) {
    const keys = c && typeof c === 'object' && !Array.isArray(c) ? Object.keys(c) : (c || []);
    return keys.map(k => `<span class="chip">${E(CH[k] || k)}</span>`).join(' ') || '<span class="dim">none</span>';
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
          <td class="adv-acts"><a class="rp-btn" href="/api/pack-library/${encodeURIComponent(p.id)}/bundle" title="Download this pack as one JSON file">JSON</a>${p.source === 'uploaded' ? `<button type="button" class="rp-btn danger" data-remove="${E(p.id)}" title="Remove this uploaded pack from the library">Remove</button>` : ''}</td>
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
      ['UI token gate', lib.ui_auth ? '<span class="chip ok">On</span> <span class="dim">every browser needs the token from ui_token.txt</span>' : '<span class="chip">Off</span> <span class="dim">ZSCALER_UI_AUTH=0 or not enforced</span>'],
      ['Changes to the Zscaler tenant', lib.writes_to_tenant ? '<span class="chip warn">Enabled</span> <span class="dim">Deploy Policy Packs and remediation can write, after your approval</span>' : '<span class="chip ok">Read-only</span> <span class="dim">the app only reads the tenant; set ZSCALER_WRITES=1 to allow deployments</span>'],
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
        <div class="df-stat"><div class="n">${c.dictionaries || 0}</div><div class="l">dictionaries${c.clones ? ` (${c.clones} clone predefined)` : ''}</div></div>
        <div class="df-stat"><div class="n">${c.engines || 0}</div><div class="l">engines</div></div>
        <div class="df-stat"><div class="n">${c.policies || 0}</div><div class="l">rules</div></div>
        <div class="df-stat"><div class="n">${(v.channels || []).length}</div><div class="l">channels: ${E((v.channels || []).map(k => CH[k] || k).join(', ') || 'none')}</div></div>
      </div>
      <details class="adv-details"><summary>Dictionaries (${(v.dictionaries || []).length})</summary>${list(v.dictionaries, d => `<li><strong>${E(d.name)}</strong> <span class="dim">${d.clone ? 'clone of ' + E(d.template || 'predefined') : `${d.patterns} pattern${d.patterns === 1 ? '' : 's'}, ${d.phrases} phrase${d.phrases === 1 ? '' : 's'}`}${d.proximity ? ', proximity ' + d.proximity : ''}</span></li>`)}</details>
      <details class="adv-details"><summary>Engines (${(v.engines || []).length})</summary>${list(v.engines, e => `<li><strong>${E(e.name)}</strong> <code class="adv-expr">${E(e.expression)}</code></li>`)}</details>
      <details class="adv-details"><summary>Rules (${(v.policies || []).length})</summary>${list(v.policies, p => `<li><strong>${E(p.name)}</strong> <span class="chip">${E(CH[p.channel] || p.channel)}</span> <span class="dim">${E(p.action || '')} · ${E(p.state || '')}${p.engines && p.engines.length ? ' · ' + E(p.engines.join(', ')) : ''}${p.sub_rules ? ` · ${p.sub_rules} sub-rule${p.sub_rules === 1 ? '' : 's'}` : ''}</span></li>`)}</details>`;
  }

  async function addPack() {
    if (!preview || !preview.ok) return;
    $('advAdd').disabled = true;
    try {
      const r = await api('/api/pack-library/upload', payload());
      const p = r.pack || {};
      say('ok', `<strong>Added “${E(p.name || p.id)}”.</strong> It is now offered in Deploy Policy Packs, the Data Flow Map and the Terraform hand-off. Rules are created DISABLED when deployed, so nothing changes in the tenant until you review and enable them.`);
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

  // ---- wiring ---------------------------------------------------------------
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
