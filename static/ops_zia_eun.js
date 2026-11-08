/* Block page theme on Bulk changes (/report/operations, "Build new").
   The editor, the preview and the download are local and read-only
   (block_page_theme.py: /api/block-page/*): nothing reaches a tenant from
   them. Applying a saved theme is the shared engine's operation
   zia_eun_theme (ops_zia_eun.py): Preview shows each field before and
   after, then the gates, the typed phrase APPLY EUN, the read-back and Undo.
   The generated page is shown only in a frame with sandbox="" (no script, no
   same-origin); every other value is escaped (H.E). */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;
  const TEXT = [['org_name', 'Organization name', 80], ['title', 'Title', 80], ['support_email', 'Support email', 254],
    ['support_phone', 'Support phone', 30], ['policy_link', 'Policy link (https://)', 300]];
  const COLORS = [['background', 'Page background'], ['card', 'Card'], ['text', 'Text'], ['accent', 'Accent and button']];
  const SWITCHES = [['show_reason', 'Show why it was blocked'], ['show_company_name', 'Show the organization name'], ['show_logo', 'Show the logo']];

  function st(S) {
    if (!S.eun) S.eun = { name: 'default', settings: null, html: '', warnings: [], eun: {}, msg: '', logo: null, pendingLogo: '', hosted: false, hostedUrl: '' };
    return S.eun;
  }
  async function api(path, opts) {
    const r = await fetch(path, Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts || {}));
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(typeof j.detail === 'string' ? j.detail : 'The request was refused.');
    return j;
  }
  function errs(H, res) {
    const rows = Object.entries((res && res.errors) || {});
    return rows.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${rows.map(([k, v]) => `<li>${H.E(k)}: ${H.E(v)}</li>`).join('')}</ul></div>` : '';
  }
  function collect(where, z) {
    const s = Object.assign({}, z.settings);
    TEXT.forEach(([k]) => { const el = where.querySelector(`[data-k="${k}"]`); if (el) s[k] = el.value; });
    const m = where.querySelector('[data-k="message"]'); if (m) s.message = m.value;
    COLORS.forEach(([k]) => { const el = where.querySelector(`[data-k="${k}"]`); if (el) s[k] = el.value; });
    SWITCHES.forEach(([k]) => { const el = where.querySelector(`[data-k="${k}"]`); if (el) s[k] = el.checked; });
    z.settings = s;
    const hc = where.querySelector('[data-k="hosted"]'), hu = where.querySelector('[data-k="hostedUrl"]');
    if (hc) z.hosted = hc.checked;
    if (hu) z.hostedUrl = hu.value.trim();
    return s;
  }
  function render(res, where, S, H) {
    const E = H.E, z = st(S), themes = res.themes || [];
    const draw = async () => {
      if (!z.settings) { const d = await api('/api/block-page/themes'); z.settings = Object.assign({}, d.defaults); const t = (d.themes || []).find(x => x.name === z.name); if (t) { z.settings = t.settings; z.logo = t.logo; } }
      const s = z.settings;
      where.innerHTML = `${errs(H, res)}
        <p class="df-hint">${E(res.visible || '')} ${E(res.logo_note || '')}</p>
        <div class="op-row"><label class="df-ctl"><span class="lbl">Theme name</span><input data-n="name" value="${E(z.name)}" maxlength="40" aria-label="Theme name"></label>
          <span class="df-hint">Saved: ${themes.map(t => E(t.name)).join(', ') || 'none yet'}</span></div>
        <div class="op-row">${TEXT.map(([k, l, n]) => `<label class="df-ctl"><span class="lbl">${E(l)}</span><input data-k="${E(k)}" value="${E(s[k] || '')}" maxlength="${E(n)}" aria-label="${E(l)}"></label>`).join('')}</div>
        <div class="op-row"><label class="df-ctl"><span class="lbl">Message</span><textarea data-k="message" rows="3" maxlength="600" aria-label="Message to blocked users">${E(s.message || '')}</textarea></label></div>
        <div class="op-row">${COLORS.map(([k, l]) => `<label class="df-ctl"><span class="lbl">${E(l)}</span><input type="color" data-k="${E(k)}" value="${E(s[k])}" aria-label="${E(l)}"></label>`).join('')}</div>
        <div class="op-row">${SWITCHES.map(([k, l]) => `<label class="df-ctl"><input type="checkbox" data-k="${E(k)}"${s[k] ? ' checked' : ''}><span>${E(l)}</span></label>`).join('')}</div>
        <div class="op-row"><label class="df-ctl"><span class="lbl">Logo (PNG, JPEG or GIF, up to 200 KB)</span><input type="file" id="eunLogo" accept="image/png,image/jpeg,image/gif" aria-label="Logo image"></label>
          <span class="df-hint">${z.logo ? `Stored: ${E(z.logo.mime)}, ${E(z.logo.bytes)} bytes.` : 'No logo stored.'}${z.pendingLogo ? ' A new logo is chosen and is stored when you save.' : ''}</span></div>
        <div class="op-row"><label class="df-ctl"><input type="checkbox" data-k="hosted"${z.hosted ? ' checked' : ''}><span>Use my hosted block page</span></label>
          <label class="df-ctl"><span class="lbl">Address of your hosted page (https://, no user name or password)</span><input data-k="hostedUrl" value="${E(z.hostedUrl)}" maxlength="1024" placeholder="https://blocked.example.com/page.html" aria-label="Hosted block page address"></label>
          <span class="df-hint">${E(res.hosted_note || '')} Download the HTML below, host it there, then press Preview in the operation panel: Apply sets the notification type to CUSTOM and the redirect address to this one.</span></div>
        <div class="op-row"><button type="button" class="rp-btn" id="eunPreview">Preview</button> <button type="button" class="rp-btn" id="eunSave">Save theme</button>
          <a class="rp-btn" id="eunDownload" href="/api/block-page/export?name=${encodeURIComponent(z.name)}" download>Download HTML</a>
          <span class="df-hint" id="eunMsg" role="status" aria-live="polite">${E(z.msg)}</span></div>
        ${z.warnings.length ? `<div class="bp-card warn" role="note"><div class="t">Worth a look</div><ul>${z.warnings.map(w => `<li>${E(w)}</li>`).join('')}</ul></div>` : ''}
        <div id="eunFrameBox"></div>
        <p class="df-hint">Preview and Save are local. To apply the saved theme, press Preview in the operation panel below (it reads ZIA), then Apply.</p>`;
      const box = H.$('eunFrameBox');
      if (box && z.html) {
        const fr = document.createElement('iframe');
        fr.id = 'eunFrame'; fr.setAttribute('title', 'Block page preview'); fr.setAttribute('sandbox', '');
        fr.style.cssText = 'width:100%;height:24rem;border:1px solid #888';
        fr.setAttribute('srcdoc', z.html);  // a blob: URL would be refused by the page CSP; the frame is sandboxed with no script and no same-origin
        const det = document.createElement('details'), sum = document.createElement('summary'), pre = document.createElement('pre');
        sum.textContent = 'Settings this theme sends to ZIA'; pre.textContent = JSON.stringify(z.eun, null, 2);
        det.append(sum, pre); box.append(fr, det);
      }
      where.querySelector('[data-k="hosted"]').addEventListener('change', e => { z.hosted = e.target.checked; });
      where.querySelector('[data-k="hostedUrl"]').addEventListener('input', e => { z.hostedUrl = e.target.value.trim(); });
      where.querySelector('[data-n="name"]').addEventListener('input', e => { z.name = e.target.value.trim().toLowerCase(); });
      H.$('eunLogo').addEventListener('change', e => {
        const f = e.target.files[0]; if (!f) return;
        if (f.size > 200 * 1024) { z.msg = 'The logo is larger than 200 KB.'; collect(where, z); draw(); return; }
        const rd = new FileReader();
        rd.onload = () => { z.pendingLogo = String(rd.result); z.msg = 'Logo chosen; save to store it.'; collect(where, z); draw(); };
        rd.readAsDataURL(f);
      });
      const run = async (fn) => { try { collect(where, z); await fn(); } catch (e) { z.msg = e.message; } draw(); };
      H.$('eunPreview').addEventListener('click', () => run(async () => {
        const o = await api('/api/block-page/preview', { method: 'POST', body: JSON.stringify({ name: z.name, settings: z.settings }) });
        z.html = o.html; z.warnings = o.warnings; z.eun = o.eun_settings; z.msg = 'Preview made (nothing was sent to a tenant).';
      }));
      H.$('eunSave').addEventListener('click', () => run(async () => {
        const o = await api('/api/block-page/theme', { method: 'PUT', body: JSON.stringify({ name: z.name, settings: z.settings, logo: z.pendingLogo }) });
        z.logo = o.logo; z.pendingLogo = ''; z.msg = 'Theme saved locally.';
        if (!themes.some(t => t.name === o.name)) themes.push({ id: o.name, name: o.name });
      }));
    };
    draw().catch(e => { where.innerHTML = `<div class="bp-card warn">${E(e.message)}</div>`; });
  }
  function spec(S) {
    const z = st(S);
    if (!z.name) throw new Error('Name and save a theme first.');
    const sp = { type: 'zia_eun_theme', theme: z.name };
    if (z.hosted) {
      if (!/^https:\/\/[^\s@\\]+$/.test(z.hostedUrl || '')) throw new Error('Type the https:// address of your hosted block page (no user name or password).');
      sp.hosted_url = z.hostedUrl;
    }
    return sp;
  }

  window.OPS_PLUGINS.register({ type: 'zia_eun_theme', render, spec });
})();
