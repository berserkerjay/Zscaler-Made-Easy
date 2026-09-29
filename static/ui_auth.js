// In-app dialogs for the app's own sign-in and its verdicts — never the
// browser's prompt()/alert(), which an embedded browser may not support
// (the audit saw "prompt() is not supported" surface as "the tool's own
// server did not answer").
//
//   window.dlpDialog.unlock(message)  → Promise<string|null>   the UI token, or null on cancel
//   window.dlpDialog.notice({title, body, detail, tone})  → Promise<void>  an accessible alert dialog
//   window.__dlpUnlockDialog           the unlock, for the fetch wrappers (index.html, report_theme.js)
//
// Both are native <dialog> elements: modal, labelled, Escape closes, focus
// goes in on open and back to the opener on close. Secrets typed here are
// sent once to /api/auth/unlock by the caller and never kept in the DOM.
(function () {
  if (window.dlpDialog) return;
  const CSS = `
    dialog.dlp-dlg { border: 1px solid var(--border, #334155); border-radius: var(--r-lg, 12px); padding: 0; max-width: min(92vw, 480px); width: 100%;
      background: var(--card-solid, #1c1c1e); color: var(--text, #fff); box-shadow: var(--shadow-lg, 0 12px 32px rgba(0,0,0,0.45)); font: inherit; }
    dialog.dlp-dlg::backdrop { background: rgba(0,0,0,0.45); }
    .dlp-dlg-body { padding: var(--sp-5, 20px) var(--sp-6, 24px) var(--sp-6, 24px); }
    .dlp-dlg h2 { margin: 0 0 var(--sp-2, 8px); font-size: var(--fs-title3, 1rem); font-weight: 600; display: flex; align-items: center; gap: var(--sp-2, 8px); }
    .dlp-dlg .dlp-dlg-tone { display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: var(--accent, #0a84ff); flex: none; }
    .dlp-dlg.ok .dlp-dlg-tone { background: var(--pass, #30d158); } .dlp-dlg.bad .dlp-dlg-tone { background: var(--fail, #ff453a); }
    .dlp-dlg p { margin: var(--sp-1, 4px) 0; line-height: 1.5; font-size: var(--fs-callout, 0.875rem); }
    .dlp-dlg .dlp-dlg-fix { margin-top: var(--sp-3, 12px); padding: var(--sp-2, 8px) var(--sp-3, 12px); border-left: 3px solid var(--accent, #0a84ff); background: var(--well, #2c2c2e); border-radius: var(--r-sm, 6px); }
    .dlp-dlg details { margin-top: var(--sp-3, 12px); font-size: var(--fs-subhead, 0.8125rem); } .dlp-dlg details summary { cursor: pointer; color: var(--dim, #98989f); }
    .dlp-dlg code { display: block; white-space: pre-wrap; word-break: break-word; margin-top: var(--sp-2, 8px); padding: var(--sp-2, 8px) var(--sp-3, 12px); border-radius: var(--r-sm, 6px);
      background: var(--well, #2c2c2e); border: 1px solid var(--border, #334155); font-size: var(--fs-footnote, 0.75rem); max-height: 10rem; overflow: auto; }
    .dlp-dlg label { display: block; margin: var(--sp-3, 12px) 0 var(--sp-1, 4px); font-size: var(--fs-subhead, 0.8125rem); color: var(--dim, #98989f); }
    .dlp-dlg input { width: 100%; box-sizing: border-box; min-height: var(--ctl-md, 36px); padding: var(--sp-2, 8px) var(--sp-3, 12px); border-radius: var(--r-md, 10px); border: 1px solid var(--border, #334155);
      background: var(--card-solid, #1c1c1e); color: inherit; font: inherit; }
    .dlp-dlg .dlp-dlg-err { color: var(--fail, #ff453a); font-size: var(--fs-subhead, 0.8125rem); min-height: 1.2em; margin-top: var(--sp-2, 8px); }
    .dlp-dlg .dlp-dlg-actions { display: flex; gap: var(--sp-2, 8px); justify-content: flex-end; margin-top: var(--sp-4, 16px); }
    .dlp-dlg button { font: inherit; font-weight: 600; min-height: var(--ctl-md, 36px); padding: 0 var(--sp-4, 16px); border-radius: var(--r-md, 10px); cursor: pointer; border: 1px solid var(--border, #334155); background: transparent; color: inherit; }
    .dlp-dlg button.primary { background: var(--btn, #0a84ff); border-color: transparent; color: #fff; }
    .dlp-dlg button:focus-visible, .dlp-dlg input:focus-visible, .dlp-dlg summary:focus-visible { outline: 2px solid var(--accent, #0a84ff); outline-offset: 2px; }
    body.theme-light dialog.dlp-dlg { background: var(--card-solid, #fff); color: var(--text, #000); } body.theme-light .dlp-dlg input { background: var(--card-solid, #fff); }`;
  let styled = false;
  function ensureStyle() {
    if (styled || !document.head) return;
    const s = document.createElement('style'); s.id = 'dlpDialogStyle'; s.textContent = CSS; document.head.appendChild(s); styled = true;
  }
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const supported = () => typeof HTMLDialogElement === 'function' && !!document.body;

  function open(html, cls, onReady) {
    ensureStyle();
    const opener = document.activeElement;
    const dlg = document.createElement('dialog');
    dlg.className = 'dlp-dlg ' + (cls || '');
    dlg.setAttribute('aria-labelledby', 'dlpDlgTitle');
    dlg.innerHTML = `<div class="dlp-dlg-body">${html}</div>`;
    document.body.appendChild(dlg);
    return new Promise(resolve => {
      const done = value => { try { dlg.close(); } catch (e) {} dlg.remove(); if (opener && opener.focus) { try { opener.focus(); } catch (e) {} } resolve(value); };
      dlg.addEventListener('cancel', e => { e.preventDefault(); done(null); });
      onReady(dlg, done);
      try { dlg.showModal(); } catch (e) { done(null); return; }
      const first = dlg.querySelector('input, button.primary, button');
      if (first) first.focus();
    });
  }

  async function unlock(message) {
    if (!supported()) {
      // No dialog element or no body yet: the classic prompt, guarded so an
      // unsupported prompt() becomes "cancelled", never an exception.
      try { return window.prompt((message || 'This server asks for its UI token.') + '\n\nIt is in ui_token.txt next to the app (also printed on the server console). Paste it here:'); }
      catch (e) { return null; }
    }
    return open(`
      <h2 id="dlpDlgTitle"><span class="dlp-dlg-tone" aria-hidden="true"></span>Unlock this app</h2>
      <p>${esc(message || 'This server asks for its UI token before it shows anything.')}</p>
      <p>The token is in <strong>ui_token.txt</strong> next to the app, and printed on the server console when it starts. It is this machine's own sign-in, not your Zscaler credentials.</p>
      <form method="dialog" id="dlpUnlockForm">
        <label for="dlpUnlockToken">UI token</label>
        <input id="dlpUnlockToken" type="password" autocomplete="off" spellcheck="false" aria-describedby="dlpUnlockErr">
        <div class="dlp-dlg-err" id="dlpUnlockErr" role="alert"></div>
        <div class="dlp-dlg-actions"><button type="button" id="dlpUnlockCancel">Cancel</button><button type="submit" class="primary" id="dlpUnlockGo">Unlock</button></div>
      </form>`, 'unlock', (dlg, done) => {
      dlg.querySelector('#dlpUnlockCancel').addEventListener('click', () => done(null));
      dlg.querySelector('#dlpUnlockForm').addEventListener('submit', e => {
        e.preventDefault();
        const t = dlg.querySelector('#dlpUnlockToken').value.trim();
        if (!t) { dlg.querySelector('#dlpUnlockErr').textContent = 'Paste the token first.'; return; }
        done(t);
      });
    });
  }

  function notice({ title, body, fix, detail, tone, okLabel } = {}) {
    if (!supported()) { try { window.alert(`${title || ''}\n\n${body || ''}${fix ? '\n' + fix : ''}`); } catch (e) {} return Promise.resolve(); }
    return open(`
      <h2 id="dlpDlgTitle"><span class="dlp-dlg-tone" aria-hidden="true"></span>${esc(title || 'Notice')}</h2>
      ${body ? `<p>${esc(body)}</p>` : ''}
      ${fix ? `<div class="dlp-dlg-fix"><strong>What to do:</strong> ${esc(fix)}</div>` : ''}
      ${detail ? `<details><summary>Technical detail</summary><code>${esc(detail)}</code></details>` : ''}
      <div class="dlp-dlg-actions"><button type="button" class="primary" id="dlpNoticeOk">${esc(okLabel || 'OK')}</button></div>`,
      tone === 'ok' ? 'ok' : tone === 'bad' ? 'bad' : '', (dlg, done) => {
        dlg.querySelector('#dlpNoticeOk').addEventListener('click', () => done(true));
      }).then(() => undefined);
  }

  window.dlpDialog = { unlock, notice };
  window.__dlpUnlockDialog = unlock;
})();
