// Advanced settings: update notifications (update_notify.py) and local
// plugins (local_plugins.py). Both are off by default; turning them on, and
// approving a plugin's exact SHA-256 (with its name typed), is for a writer.
(function () {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const $ = id => document.getElementById(id);

  async function call(method, path, body) {
    const r = await fetch(path, body === undefined ? { cache: 'no-store' } : { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((d && d.detail) || `Error ${r.status}`);
    return d;
  }

  // ── Update notifications ──
  function notifyNote(n) {
    const ch = (n && n.channels) || {};
    const where = [ch.email ? `e-mail to ${ch.email_to}` : '', ch.webhook ? `the webhook at ${ch.webhook_host}` : ''].filter(Boolean).join(' and ');
    const last = n && n.last ? ` Last notice: ${n.last.result} for ${n.last.commit} (${n.last.at}).` : '';
    $('advUpdNotifyNote').textContent = (n && n.enabled
      ? (where ? `On: a newer version is announced once, by ${where} (the same channel as the digests).` : 'On, but no e-mail or webhook is set up for the digests yet (DLP_CHECK_SMTP_HOST and DLP_CHECK_DIGEST_TO, or DLP_CHECK_DIGEST_WEBHOOK), so nothing is sent.')
      : 'Off: nothing is sent when a newer version is out.') + last;
  }
  async function loadNotify() {
    try {
      const n = await call('GET', '/api/app/update/notify');
      $('advUpdNotify').checked = !!n.enabled;
      notifyNote(n);
    } catch (e) { $('advUpdNotifyNote').textContent = `Could not read the setting: ${e.message}`; }
  }
  $('advUpdNotify').addEventListener('change', async e => {
    const want = e.target.checked;
    try { notifyNote(await call('PUT', '/api/app/update/notify', { enabled: want })); }
    catch (err) { e.target.checked = !want; $('advUpdNotifyNote').textContent = `Not saved: ${err.message}`; }
  });

  // ── Local plugins ──
  const STATUS = { approved: 'approved', not_approved: 'not approved', changed: 'changed since approval: refused', refused: 'refused' };
  function render(d) {
    $('advPlugOn').checked = !!d.switch;
    $('advPlugNote').textContent = !d.folder_configured
      ? `No plugins folder is set (${d.env}), so nothing is looked for and nothing can load.`
      : `${d.enabled ? 'On' : 'Off'}: folder ${d.folder}. ${d.note}`;
    const rows = d.plugins || [];
    $('advPlugins').tBodies[0].innerHTML = rows.length ? rows.map(p => `<tr>
        <td><strong>${E(p.name)}</strong><div class="dim">${E(p.description || p.reason || '')}</div></td>
        <td>${E(p.version)}</td><td><code class="adv-hash">${E(p.sha256)}</code></td>
        <td>${E((p.permissions || []).map(x => (d.permissions || {})[x] || x).join('; '))}</td>
        <td>${E(STATUS[p.status] || p.status)}${p.loaded ? ' · loaded' : ''}${p.status !== 'approved' && p.reason ? `<div class="dim">${E(p.reason)}</div>` : ''}${(p.users || []).length ? `<div class="dim">for ${E(p.users.join(', '))}</div>` : ''}</td>
        <td>${p.status === 'refused' ? '' : p.status === 'approved'
          ? `<button type="button" class="rp-btn" data-revoke="${E(p.name)}">Revoke</button>`
          : `<button type="button" class="rp-btn" data-approve="${E(p.name)}" data-sha="${E(p.sha256)}">Approve this hash</button>`}</td></tr>`).join('')
      : `<tr><td colspan="6" class="dim">${d.folder_configured ? 'No plugin packages in the folder.' : 'No plugins folder.'}</td></tr>`;
    $('advPlugins').querySelectorAll('button[data-approve]').forEach(b => b.addEventListener('click', () => approve(b.dataset.approve, b.dataset.sha)));
    $('advPlugins').querySelectorAll('button[data-revoke]').forEach(b => b.addEventListener('click', () => revoke(b.dataset.revoke)));
  }
  async function load() {
    try { render(await call('GET', '/api/plugins')); }
    catch (e) { $('advPlugNote').textContent = `Could not read the plugins: ${e.message}`; }
  }
  async function approve(name, sha) {
    const typed = window.prompt(`Approve the plugin ${name} with SHA-256 ${sha}?\n\nIt will run inside this app with the app's privileges when the app next starts. Read its code first.\n\nType the plugin's name to approve it:`);
    if (typed === null) return;
    const users = (window.prompt('Only for these people (sign-in names, separated by commas). Leave empty for everyone:') || '')
      .split(',').map(x => x.trim()).filter(Boolean);
    try { render(await call('POST', '/api/plugins/approve', { name, sha256: sha, confirm: typed.trim(), users })); $('advPlugNote').textContent = `${name} approved: it loads when the app next starts.`; }
    catch (e) { $('advPlugNote').textContent = `Not approved: ${e.message}`; }
  }
  async function revoke(name) {
    try { render(await call('POST', '/api/plugins/revoke', { name })); $('advPlugNote').textContent = `${name} revoked and unloaded.`; }
    catch (e) { $('advPlugNote').textContent = `Not revoked: ${e.message}`; }
  }
  $('advPlugOn').addEventListener('change', async e => {
    const want = e.target.checked;
    try { render(await call('PUT', '/api/plugins/settings', { enabled: want })); }
    catch (err) { e.target.checked = !want; $('advPlugNote').textContent = `Not saved: ${err.message}`; }
  });

  loadNotify();
  load();
})();
