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
    if (!S.eun) S.eun = { name: 'default', settings: null, html: '', warnings: [], eun: {}, msg: '', logo: null, pendingLogo: '' };
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
        <div class="op-row">${TEXT.map(([k, l, n]) => `<label class="df-ctl"><span class="lbl">${E(l)}</span><input data-k="${k}" value="${E(s[k] || '')}" maxlength="${n}" aria-label="${E(l)}"></label>`).join('')}</div>
        <div class="op-row"><label class="df-ctl"><span class="lbl">Message</span><textarea data-k="message" rows="3" maxlength="600" aria-label="Message to blocked users">${E(s.message || '')}</textarea></label></div>
        <div class="op-row">${COLORS.map(([k, l]) => `<label class="df-ctl"><span class="lbl">${E(l)}</span><input type="color" data-k="${k}" value="${E(s[k])}" aria-label="${E(l)}"></label>`).join('')}</div>
        <div class="op-row">${SWITCHES.map(([k, l]) => `<label class="df-ctl"><input type="checkbox" data-k="${k}"${s[k] ? ' checked' : ''}><span>${E(l)}</span></label>`).join('')}</div>
        <div class="op-row"><label class="df-ctl"><span class="lbl">Logo (PNG, JPEG or GIF, up to 200 KB)</span><input type="file" id="eunLogo" accept="image/png,image/jpeg,image/gif" aria-label="Logo image"></label>
          <span class="df-hint">${z.logo ? `Stored: ${E(z.logo.mime)}, ${E(z.logo.bytes)} bytes.` : 'No logo stored.'}${z.pendingLogo ? ' A new logo is chosen and is stored when you save.' : ''}</span></div>
        <div class="op-row"><button type="button" class="rp-btn" id="eunPreview">Preview</button> <button type="button" class="rp-btn" id="eunSave">Save theme</button>
          <a class="rp-btn" id="eunDownload" href="/api/block-page/export?name=${encodeURIComponent(z.name)}" download>Download HTML</a>
          <span class="df-hint" id="eunMsg" role="status" aria-live="polite">${E(z.msg)}</span></div>
        ${z.warnings.length ? `<div class="bp-card warn" role="note"><div class="t">Worth a look</div><ul>${z.warnings.map(w => `<li>${E(w)}</li>`).join('')}</ul></div>` : ''}
        ${z.html ? `<iframe id="eunFrame" title="Block page preview" sandbox="" style="width:100%;height:24rem;border:1px solid #888"></iframe>
          <details><summary>Settings this theme sends to ZIA</summary><pre>${E(JSON.stringify(z.eun, null, 2))}</pre></details>` : ''}
        <p class="df-hint">Preview and Save are local. To apply the saved theme, press Preview in the operation panel below (it reads ZIA), then Apply.</p>`;
      const fr = H.$('eunFrame'); if (fr) fr.srcdoc = z.html;
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
    return { type: 'zia_eun_theme', theme: z.name };
  }

  window.OPS_PLUGINS.register({ type: 'zia_eun_theme', render, spec });
})();
