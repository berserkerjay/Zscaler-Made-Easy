/* ZIdentity users and API clients on Bulk changes (/report/operations,
   "Day-to-day admin"), on the shared engine (ops_zid.py). The page does the
   rest: Read from the tenant, Preview, the four gates, Apply, Undo. A new API
   client secret is fetched once after the apply (POST
   /api/operations/zidentity/secret), shown in a read-only box and never kept
   by the page. Every tenant string is escaped (H.E). */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;
  let E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function errs(res) {
    const rows = Object.entries((res && res.errors) || {});
    return rows.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${rows.map(([k, v]) => `<li>${E(k)}: ${E(v)}</li>`).join('')}</ul></div>` : '';
  }
  function notes(res) {
    return `<ul class="op-checks">${(res.not_possible || []).map(n => `<li class="df-hint">${E(n)}</li>`).join('')}</ul>`;
  }

  // ── Users ──
  function zu(S) {
    if (!S.zu) S.zu = { mode: 'change', act: 'disable', pick: new Set(), login: '', display: '', first: '', last: '', enable: false };
    return S.zu;
  }
  function renderUsers(res, where, S, H) {
    const z = zu(S), users = res.users || [];
    const body = z.mode === 'change' ? `
      <div class="op-row"><label class="df-ctl"><span class="lbl">Find users by login name</span><input id="zuSearch" type="search" value="${E(res.query || '')}" maxlength="100" aria-label="Find users by login name (contains)"></label>
        <button type="button" class="rp-btn" id="zuSearchGo">Search</button>
        <span class="df-hint">${E(users.length)} user${users.length === 1 ? '' : 's'}${res.users_truncated ? ', the first ones only: search to narrow' : ''}.</span></div>
      <div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">ZIdentity users</caption>
        <thead><tr><th scope="col">Pick</th><th scope="col">User</th><th scope="col">State</th><th scope="col">Source</th><th scope="col">Note</th></tr></thead>
        <tbody>${users.map(u => `<tr><td><input type="checkbox" data-zid-u="${E(u.id)}" aria-label="Pick ${E(u.login_name)}"${z.pick.has(u.id) ? ' checked' : ''}${u.locked ? ' disabled' : ''}></td>
          <td>${E(u.display_name)}<div class="df-by">${E(u.login_name)}</div></td><td><span class="df-chip ${u.status === 'enabled' ? 'st-ok' : ''}">${E(u.status)}</span></td>
          <td>${E(u.source)}</td><td class="df-hint">${E(u.locked)}</td></tr>`).join('') || '<tr><td colspan="5">No user matches.</td></tr>'}</tbody></table></div>
      <div class="op-row"><fieldset class="op-inline"><legend>For the picked users</legend>
        ${[['disable', 'Disable'], ['enable', 'Enable'], ['delete', 'Delete (cannot be undone)']].map(([v, l]) => `<label><input type="radio" name="zuAct" value="${E(v)}"${z.act === v ? ' checked' : ''}> ${E(l)}</label>`).join('')}</fieldset></div>`
      : `<div class="op-row"><label class="df-ctl"><span class="lbl">Login name</span><input id="zuLogin" type="email" value="${E(z.login)}" maxlength="254" aria-label="Login name" placeholder="sam.lee@example.com"></label>
          <label class="df-ctl"><span class="lbl">Display name</span><input id="zuDisplay" value="${E(z.display)}" maxlength="255" aria-label="Display name" placeholder="Sam Lee"></label></div>
        <div class="op-row"><label class="df-ctl"><span class="lbl">First name</span><input id="zuFirst" value="${E(z.first)}" maxlength="255" aria-label="First name"></label>
          <label class="df-ctl"><span class="lbl">Last name</span><input id="zuLast" value="${E(z.last)}" maxlength="255" aria-label="Last name"></label></div>
        <div class="op-row"><label class="df-ctl"><input type="checkbox" id="zuEnable"${z.enable ? ' checked' : ''}><span>Enable the user when it is created (off by default)</span></label></div>
        <div class="df-hint">No password is set here.</div>`;
    where.innerHTML = `${errs(res)}
      <div class="op-row"><fieldset class="op-inline"><legend>What to do</legend>
        <label><input type="radio" name="zuMode" value="change"${z.mode === 'change' ? ' checked' : ''}> Disable, enable or delete users</label>
        <label><input type="radio" name="zuMode" value="create"${z.mode === 'create' ? ' checked' : ''}> Add a user</label></fieldset></div>
      ${body}${notes(res)}`;
    const again = id => { renderUsers(res, where, S, H); const el = document.getElementById(id) || where.querySelector(`input[name="${id}"]:checked`); if (el) el.focus(); };
    where.querySelectorAll('input[name="zuMode"]').forEach(r => r.addEventListener('change', () => { z.mode = r.value; again('zuMode'); }));
    where.querySelectorAll('input[name="zuAct"]').forEach(r => r.addEventListener('change', () => { z.act = r.value; }));
    where.querySelectorAll('input[data-zid-u]').forEach(cb => cb.addEventListener('change', () => { cb.checked ? z.pick.add(cb.dataset.zidU) : z.pick.delete(cb.dataset.zidU); }));
    [['zuLogin', 'login'], ['zuDisplay', 'display'], ['zuFirst', 'first'], ['zuLast', 'last']].forEach(([id, k]) => {
      const el = document.getElementById(id); if (el) el.addEventListener('input', () => { z[k] = el.value; });
    });
    const en = document.getElementById('zuEnable'); if (en) en.addEventListener('change', () => { z.enable = en.checked; });
    const go = document.getElementById('zuSearchGo');
    if (go) {
      go.addEventListener('click', () => H.read(document.getElementById('zuSearch').value.trim()));
      document.getElementById('zuSearch').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); go.click(); } });
    }
  }
  function specUsers(S) {
    const z = zu(S);
    if (z.mode === 'create') {
      if (!z.login.trim() || !z.display.trim()) throw new Error('Give the login name and the display name.');
      return { type: 'zid_users', changes: [{ action: 'create', login_name: z.login.trim(), display_name: z.display.trim(), first_name: z.first.trim(),
        last_name: z.last.trim(), enable: !!z.enable }] };
    }
    if (!z.pick.size) throw new Error('Pick at least one user.');
    return { type: 'zid_users', changes: [...z.pick].map(id => ({ action: z.act, id })) };
  }

  // ── API clients ──
  function zk(S) {
    if (!S.zk) S.zk = { act: 'rotate', pick: '', keepOld: false, name: '', desc: '', life: 3600, scopes: new Set(), enable: false };
    return S.zk;
  }
  function renderClients(res, where, S, H) {
    const z = zk(S), list = res.api_clients || [], servers = res.resource_servers || [];
    const acts = [['rotate', 'Rotate the secret'], ['disable', 'Disable'], ['enable', 'Enable'], ['delete', 'Delete (cannot be undone)'], ['create', 'New API client']];
    const table = `<div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">API clients and their scopes</caption>
        <thead><tr><th scope="col">Pick</th><th scope="col">API client</th><th scope="col">State</th><th scope="col">Scopes</th><th scope="col">Note</th></tr></thead>
        <tbody>${list.map(c => `<tr><td><input type="radio" name="zkPick" value="${E(c.id)}" aria-label="Pick ${E(c.name)}"${z.pick === c.id ? ' checked' : ''}${c.own ? ' disabled' : ''}></td>
          <td>${E(c.name)}<div class="df-by">${E(c.description)}</div></td><td><span class="df-chip ${c.status === 'enabled' ? 'st-ok' : ''}">${E(c.status)}</span></td>
          <td>${(c.scopes || []).map(s => `${E(s.name)}${(c.broad || []).includes(s.name) ? ' <span class="df-chip st-warn">full access</span>' : ''}`).join('<br>') || '<span class="df-hint">none</span>'}</td>
          <td class="df-hint">${E(c.locked)}</td></tr>`).join('') || '<tr><td colspan="5">No API client.</td></tr>'}</tbody></table></div>`;
    const create = `<div class="op-row"><label class="df-ctl"><span class="lbl">Name</span><input id="zkName" value="${E(z.name)}" maxlength="128" aria-label="New API client name" placeholder="Reporting export"></label>
        <label class="df-ctl"><span class="lbl">Description</span><input id="zkDesc" value="${E(z.desc)}" maxlength="500" aria-label="Description"></label>
        <label class="df-ctl"><span class="lbl">Token lifetime (seconds)</span><input id="zkLife" type="number" min="300" max="86400" step="60" value="${E(z.life)}" aria-label="Access token lifetime in seconds"></label></div>
      <p class="df-hint">Least privilege: tick only the scopes the tool needs. Nothing is ticked for you.</p>
      <ul class="op-checks">${servers.map(r => (r.scopes || []).map(s => { const k = `${r.id}|${s.id}`; return `<li><label><input type="checkbox" data-zk-scope="${E(k)}"${z.scopes.has(k) ? ' checked' : ''}> ${E(r.name)}: ${E(s.name)}${s.broad ? ' <span class="df-chip st-warn">full access</span>' : ''}</label></li>`; }).join('')).join('')
        || '<li class="df-hint">No scope could be read.</li>'}</ul>
      <div class="op-row"><label class="df-ctl"><input type="checkbox" id="zkEnable"${z.enable ? ' checked' : ''}><span>Enable the client when it is created (off by default)</span></label></div>
      <div class="df-hint">${E(res.secret_once || '')}</div>`;
    const forPick = z.act === 'rotate' ? `<div class="op-row"><label class="df-ctl"><input type="checkbox" id="zkKeepOld"${z.keepOld ? ' checked' : ''}><span>Keep the old secrets (delete them later, once every tool has the new one)</span></label></div>
        <div class="df-hint">${E(res.secret_once || '')}</div>` : '';
    where.innerHTML = `${errs(res)}
      <div class="op-row"><fieldset class="op-inline"><legend>What to do</legend>${acts.map(([v, l]) => `<label><input type="radio" name="zkAct" value="${E(v)}"${z.act === v ? ' checked' : ''}> ${E(l)}</label>`).join('')}</fieldset></div>
      ${z.act === 'create' ? create : table + forPick}${notes(res)}`;
    const again = id => { renderClients(res, where, S, H); const el = document.getElementById(id) || where.querySelector(`input[name="${id}"]:checked`); if (el) el.focus(); };
    where.querySelectorAll('input[name="zkAct"]').forEach(r => r.addEventListener('change', () => { z.act = r.value; again('zkAct'); }));
    where.querySelectorAll('input[name="zkPick"]').forEach(r => r.addEventListener('change', () => { z.pick = r.value; }));
    where.querySelectorAll('input[data-zk-scope]').forEach(cb => cb.addEventListener('change', () => { cb.checked ? z.scopes.add(cb.dataset.zkScope) : z.scopes.delete(cb.dataset.zkScope); }));
    [['zkName', 'name'], ['zkDesc', 'desc'], ['zkLife', 'life']].forEach(([id, k]) => { const el = document.getElementById(id); if (el) el.addEventListener('input', () => { z[k] = el.value; }); });
    const keep = document.getElementById('zkKeepOld'); if (keep) keep.addEventListener('change', () => { z.keepOld = keep.checked; });
    const en = document.getElementById('zkEnable'); if (en) en.addEventListener('change', () => { z.enable = en.checked; });
  }
  function specClients(S) {
    const z = zk(S);
    if (z.act === 'create') {
      if (!String(z.name).trim()) throw new Error('Name the API client.');
      if (!z.scopes.size) throw new Error('Tick at least one scope (only what the tool needs).');
      return { type: 'zid_api_clients', action: 'create', name: String(z.name).trim(), description: String(z.desc).trim(), token_lifetime: Number(z.life) || 3600,
        scopes: [...z.scopes].map(k => { const [resource, scope] = k.split('|'); return { resource, scope }; }), enable: !!z.enable };
    }
    if (!z.pick) throw new Error('Pick the API client.');
    const spec = { type: 'zid_api_clients', action: z.act, id: z.pick };
    if (z.act === 'rotate') spec.delete_old = !z.keepOld;
    return spec;
  }

  // ── The new secret, fetched once after the apply ──
  async function showSecrets(r, where, H) {
    for (const s of r.one_time_secrets || []) {
      const box = document.createElement('div');
      box.className = 'bp-card warn';
      box.setAttribute('role', 'alert');
      where.prepend(box);
      try {
        const q = await fetch('/api/operations/zidentity/secret', { method: 'POST', headers: { 'Content-Type': 'application/json' }, cache: 'no-store', body: JSON.stringify({ token: s.token }) });
        const d = await q.json().catch(() => ({}));
        if (!q.ok) throw new Error(typeof d.detail === 'string' && d.detail ? d.detail : (d.detail && d.detail.cause) || `HTTP ${q.status}`);
        box.innerHTML = `<div class="t">New secret of ${E(d.name)}: copy it now</div>
          <div>It is shown this once. This app does not keep it; if you lose it, rotate the secret again.</div>
          <div class="op-row"><label class="df-ctl"><span class="lbl">Secret</span><input class="zk-secret" readonly autocomplete="off" spellcheck="false" aria-label="New API client secret"></label>
            <button type="button" class="rp-btn zk-copy">Copy</button></div>`;
        const inp = box.querySelector('.zk-secret'); inp.value = d.secret;
        box.querySelector('.zk-copy').addEventListener('click', async () => {
          try { await navigator.clipboard.writeText(inp.value); H.say('Copied.'); } catch (e) { inp.select(); H.say('Select the secret and copy it.'); }
        });
        H.say('The new secret is shown once: copy it now.');
      } catch (e) {
        box.innerHTML = `<div class="t">The secret could not be shown</div><div>${E(e.message)}</div>`;
      }
    }
  }

  window.OPS_PLUGINS.register({ type: 'zid_users', render(res, where, S, H) { E = H.E || E; renderUsers(res, where, S, H); }, spec: S => specUsers(S) });
  window.OPS_PLUGINS.register({ type: 'zid_api_clients', render(res, where, S, H) { E = H.E || E; renderClients(res, where, S, H); }, spec: S => specClients(S),
    result(r, where, H) { E = H.E || E; showSecrets(r, where, H); } });
}());
