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
    dialog.dlp-dlg { border: 1px solid var(--border, #334155); border-radius: 12px; padding: 0; max-width: min(92vw, 520px); width: 100%;
      background: var(--card, #0f172a); color: var(--text, #e2e8f0); box-shadow: 0 24px 64px rgba(0,0,0,0.45); font: inherit; }
    dialog.dlp-dlg::backdrop { background: rgba(2,6,23,0.6); }
    .dlp-dlg-body { padding: 1.1rem 1.25rem 1.25rem; }
    .dlp-dlg h2 { margin: 0 0 0.5rem; font-size: 1.05rem; display: flex; align-items: center; gap: 0.5rem; }
    .dlp-dlg .dlp-dlg-tone { display: inline-block; width: 0.75rem; height: 0.75rem; border-radius: 50%; background: var(--accent, #3b82f6); flex: none; }
    .dlp-dlg.ok .dlp-dlg-tone { background: var(--pass, #22c55e); } .dlp-dlg.bad .dlp-dlg-tone { background: var(--fail, #ef4444); }
    .dlp-dlg p { margin: 0.35rem 0; line-height: 1.5; font-size: 0.92rem; }
    .dlp-dlg .dlp-dlg-fix { margin-top: 0.6rem; padding: 0.6rem 0.75rem; border-left: 3px solid var(--accent, #3b82f6); background: rgba(148,163,184,0.08); border-radius: 6px; }
    .dlp-dlg details { margin-top: 0.6rem; font-size: 0.85rem; } .dlp-dlg details summary { cursor: pointer; color: var(--dim, #94a3b8); }
    .dlp-dlg code { display: block; white-space: pre-wrap; word-break: break-word; margin-top: 0.4rem; padding: 0.5rem 0.6rem; border-radius: 6px;
      background: rgba(15,23,42,0.5); border: 1px solid var(--border, #334155); font-size: 0.78rem; max-height: 10rem; overflow: auto; }
    .dlp-dlg label { display: block; margin: 0.75rem 0 0.35rem; font-size: 0.85rem; color: var(--dim, #94a3b8); }
    .dlp-dlg input { width: 100%; box-sizing: border-box; padding: 0.55rem 0.7rem; border-radius: 8px; border: 1px solid var(--border, #334155);
      background: var(--well, #0b1220); color: inherit; font: inherit; }
    .dlp-dlg .dlp-dlg-err { color: var(--fail, #ef4444); font-size: 0.85rem; min-height: 1.2em; margin-top: 0.4rem; }
    .dlp-dlg .dlp-dlg-actions { display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem; }
    .dlp-dlg button { font: inherit; font-weight: 600; padding: 0.5rem 0.95rem; border-radius: 8px; cursor: pointer; border: 1px solid var(--border, #334155); background: transparent; color: inherit; }
    .dlp-dlg button.primary { background: var(--accent, #3b82f6); border-color: var(--accent, #3b82f6); color: #fff; }
    .dlp-dlg button:focus-visible, .dlp-dlg input:focus-visible, .dlp-dlg summary:focus-visible { outline: 2px solid var(--accent, #3b82f6); outline-offset: 2px; }
    body.theme-light dialog.dlp-dlg { background: #fff; color: #0f172a; } body.theme-light .dlp-dlg input { background: #f8fafc; }`;
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
