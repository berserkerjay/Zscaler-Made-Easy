// In-app dialogs for the app's own sign-in and its verdicts — never the
// browser's prompt()/alert(), which an embedded browser may not support
// (the audit saw "prompt() is not supported" surface as "the tool's own
// server did not answer").
//
//   window.dlpDialog.unlock(message)  → Promise<string|null>   the UI token, or null on cancel
//   window.dlpDialog.notice({title, body, detail, tone})  → Promise<void>  an accessible alert dialog
//   window.dlpDialog.phrase({title, body, phrase, label})  → Promise<string|null>  a typed confirmation phrase (write mode), or null on cancel
//   window.dlpDialog.ask({title, body, okLabel, cancelLabel, tone})  → Promise<boolean>  a yes / no question
//   window.__dlpUnlockDialog           the unlock, for the fetch wrappers (index.html, report_theme.js)
//
// Both are native <dialog> elements: modal, labelled, Escape closes, focus
// goes in on open and back to the opener on close. Secrets typed here are
// sent once to /api/auth/unlock by the caller and never kept in the DOM.
(function () {
  if (window.dlpDialog) return;
  const CSS = `
    dialog.dlp-dlg { margin: auto; border: 1px solid var(--border, #334155); border-radius: var(--r-lg, 12px); padding: 0; max-width: min(92vw, 480px); width: 100%;
      background: var(--card-solid, #1c1c1e); color: var(--text, #fff); box-shadow: var(--shadow-lg, 0 12px 32px rgba(0,0,0,0.45)); font: inherit; }
    dialog.dlp-dlg::backdrop { background: rgba(0,0,0,0.45); }
    .dlp-dlg-body { padding: var(--sp-5, 20px) var(--sp-6, 24px) var(--sp-6, 24px); }
    .dlp-dlg h2 { margin: 0 0 var(--sp-2, 8px); font-size: var(--fs-title3, 1rem); font-weight: 600; display: flex; align-items: center; gap: var(--sp-2, 8px); }
    .dlp-dlg .dlp-dlg-tone { display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: var(--accent, #0a84ff); flex: none; }
    .dlp-dlg.ok .dlp-dlg-tone { background: var(--pass, #30d158); } .dlp-dlg.bad .dlp-dlg-tone { background: var(--fail, #ff453a); }
    .dlp-dlg p { margin: var(--sp-1, 4px) 0; line-height: 1.5; font-size: var(--fs-callout, 0.875rem); }
    .dlp-dlg p.dlp-dlg-pre { white-space: pre-line; overflow-wrap: anywhere; max-height: 50vh; overflow: auto; }
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
      // Escape closes this dialog only: the page behind it (the Deploy Studio sheet, say) listens for Escape too.
      dlg.addEventListener('keydown', e => { if (e.key === 'Escape') e.stopPropagation(); });
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
      try { return window.prompt((message || 'This server asks for its UI token.') + '\n\nIt is in ui_token.txt next to the app (also in server.log, or the terminal window that runs the app). Paste it here:'); }
      catch (e) { return null; }
    }
    return open(`
      <h2 id="dlpDlgTitle"><span class="dlp-dlg-tone" aria-hidden="true"></span>Unlock this app</h2>
      <p>${esc(message || 'This server asks for its UI token before it shows anything.')}</p>
      <p>The token is in <strong>ui_token.txt</strong> next to the app, and in server.log (or the terminal window that runs the app) when it starts. It is this machine's own sign-in, not your Zscaler credentials.</p>
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

  function notice({ title, body, fix, detail, tone, okLabel, pre } = {}) {
    if (!supported()) { try { window.alert(`${title || ''}\n\n${body || ''}${fix ? '\n' + fix : ''}`); } catch (e) {} return Promise.resolve(); }
    return open(`
      <h2 id="dlpDlgTitle"><span class="dlp-dlg-tone" aria-hidden="true"></span>${esc(title || 'Notice')}</h2>
      ${body ? `<p${pre ? ' class="dlp-dlg-pre"' : ''}>${esc(body)}</p>` : ''}
      ${fix ? `<div class="dlp-dlg-fix"><strong>What to do:</strong> ${esc(fix)}</div>` : ''}
      ${detail ? `<details><summary>Technical detail</summary><code>${esc(detail)}</code></details>` : ''}
      <div class="dlp-dlg-actions"><button type="button" class="primary" id="dlpNoticeOk">${esc(okLabel || 'OK')}</button></div>`,
      tone === 'ok' ? 'ok' : tone === 'bad' ? 'bad' : '', (dlg, done) => {
        dlg.querySelector('#dlpNoticeOk').addEventListener('click', () => done(true));
      }).then(() => undefined);
  }

  // A typed confirmation phrase (Enable write mode): the phrase is shown,
  // typed into a plain text field, and returned for the server to check;
  // null on Cancel or Escape. The classic prompt() only when <dialog> is
  // missing, guarded so an unsupported prompt() reads as cancelled.
  function phrase({ title, body, phrase: expected, label, okLabel, tone } = {}) {
    if (!supported()) {
      try { return Promise.resolve(window.prompt(`${title || ''}\n\n${body || ''}\n\nType ${expected || ''} to continue:`, '') || null); }
      catch (e) { return Promise.resolve(null); }
    }
    const paras = String(body || '').split(/\n\s*\n/).filter(Boolean).map(p => `<p>${esc(p)}</p>`).join('');
    return open(`
      <h2 id="dlpDlgTitle"><span class="dlp-dlg-tone" aria-hidden="true"></span>${esc(title || 'Confirm')}</h2>
      ${paras}
      <form method="dialog" id="dlpPhraseForm">
        <label for="dlpPhraseInput">${esc(label || `Type ${expected || 'the confirmation phrase'} to continue`)}</label>
        <input id="dlpPhraseInput" type="text" autocomplete="off" autocapitalize="characters" spellcheck="false" aria-describedby="dlpPhraseErr">
        <div class="dlp-dlg-err" id="dlpPhraseErr" role="alert"></div>
        <div class="dlp-dlg-actions"><button type="button" id="dlpPhraseCancel">Cancel</button><button type="submit" class="primary" id="dlpPhraseGo">${esc(okLabel || 'Continue')}</button></div>
      </form>`, tone === 'bad' ? 'bad' : '', (dlg, done) => {
      dlg.querySelector('#dlpPhraseCancel').addEventListener('click', () => done(null));
      dlg.querySelector('#dlpPhraseForm').addEventListener('submit', e => {
        e.preventDefault();
        const t = dlg.querySelector('#dlpPhraseInput').value.trim();
        if (!t) { dlg.querySelector('#dlpPhraseErr').textContent = `Type ${expected || 'the phrase'} first.`; return; }
        if (expected && t !== expected) { dlg.querySelector('#dlpPhraseErr').textContent = `That is not ${expected}. Type it exactly as shown above.`; return; }
        done(t);
      });
    });
  }

  // A yes / no question (Back to read-only): true on the primary button,
  // false on Cancel or Escape. window.confirm() only when <dialog> is
  // missing, guarded the same way.
  function ask({ title, body, okLabel, cancelLabel, tone } = {}) {
    if (!supported()) {
      try { return Promise.resolve(!!window.confirm(`${title || ''}\n\n${body || ''}`)); } catch (e) { return Promise.resolve(false); }
    }
    return open(`
      <h2 id="dlpDlgTitle"><span class="dlp-dlg-tone" aria-hidden="true"></span>${esc(title || 'Are you sure?')}</h2>
      ${body ? `<p>${esc(body)}</p>` : ''}
      <div class="dlp-dlg-actions"><button type="button" id="dlpAskCancel">${esc(cancelLabel || 'Cancel')}</button><button type="button" class="primary" id="dlpAskGo">${esc(okLabel || 'OK')}</button></div>`,
      tone === 'bad' ? 'bad' : '', (dlg, done) => {
        dlg.querySelector('#dlpAskCancel').addEventListener('click', () => done(false));
        dlg.querySelector('#dlpAskGo').addEventListener('click', () => done(true));
      }).then(v => v === true);
  }

  // SSO only (ZSCALER_SSO_ENABLED): a small "Signed in as … · Sign out"
  // control, or "Sign in" once the session has ended. Without SSO nothing
  // is shown and the UI token works as before.
  let ssoStatus = null;
  // A sign-in or sign-out address from the server is used only as a path on
  // this origin ("/..."): never another site, a protocol-relative "//host",
  // a backslash trick or a javascript: URL (deny by default, fall back to the fixed path).
  const safeHref = (u, fallback) => (typeof u === 'string' && /^\/(?![\/\\])[^\s\\]*$/.test(u) && u.length <= 512) ? u : fallback;
  function ssoBar(status) {
    if (status && typeof status === 'object') {
      status.sso_login_url = safeHref(status.sso_login_url, '/api/auth/sso/login');
      status.logout_url = safeHref(status.logout_url, '/api/auth/logout');
    }
    ssoStatus = status;
    if (!status || !status.sso || !document.body || window.top !== window) return;
    let bar = document.getElementById('dlpSsoBar');
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'dlpSsoBar';
      bar.setAttribute('role', 'region');
      bar.setAttribute('aria-label', 'Sign-in');
      bar.style.cssText = 'position:fixed;top:8px;right:12px;z-index:9999;display:flex;gap:8px;align-items:center;font-size:var(--fs-footnote,0.75rem);'
        + 'padding:4px 8px;border-radius:var(--r-md,10px);border:1px solid var(--border,#334155);background:var(--card-solid,#1c1c1e);color:var(--text,#fff);';
      document.body.appendChild(bar);
    }
    const btn = 'font:inherit;font-weight:600;cursor:pointer;border:1px solid var(--border,#334155);border-radius:var(--r-sm,6px);background:transparent;color:inherit;padding:2px 8px;';
    if (status.unlocked) {
      bar.innerHTML = `<span>Signed in as <strong>${esc(status.user || 'you')}</strong>${status.may_write === false ? ' (read and preview only)' : ''}</span>`
        + (status.team ? `<a href="/report/team" id="dlpTeamLink" style="${btn}text-decoration:none;">Team server</a>` : '')
        + `<button type="button" id="dlpSignOut" style="${btn}">Sign out</button>`;
      bar.querySelector('#dlpSignOut').addEventListener('click', async () => {
        try { await fetch(status.logout_url || '/api/auth/logout', { method: 'POST', credentials: 'same-origin' }); } catch (e) {}
        window.location.href = '/';
      });
    } else {
      bar.innerHTML = `<span>Not signed in</span><a href="${esc(status.sso_login_url || '/api/auth/sso/login')}" style="${btn}text-decoration:none;">Sign in</a>`;
    }
  }
  // Idle-timeout warning (SSO and team server sessions; the UI token has no
  // idle limit). Every request this page makes keeps the session alive on the
  // server, so the page counts its own requests (Resource Timing) as activity.
  // Two minutes before the idle limit it asks "Still there?": Stay signed in
  // makes one request (which renews the session), Sign out ends it. At the
  // limit it goes to the sign-in page. Five minutes before the session's
  // absolute end it says when that is: that end cannot be pushed back.
  const IDLE_WARN_S = 120, END_WARN_S = 300;
  let idleTimer = null;
  function startIdleWatch(status) {
    if (idleTimer || !status || !status.unlocked || !(status.idle_seconds > 0) || window.top !== window) return;
    const idle = Number(status.idle_seconds), loadedAt = Date.now(), endAt = loadedAt + 1000 * Number(status.expires_in || 0);
    let last = Date.now(), asking = false, endWarned = false;
    const touch = () => { last = Date.now(); };
    try {
      new PerformanceObserver(list => {
        for (const e of list.getEntries()) {
          if ((e.initiatorType === 'fetch' || e.initiatorType === 'xmlhttprequest') && String(e.name).startsWith(location.origin + '/')) touch();
        }
      }).observe({ type: 'resource', buffered: false });
    } catch (e) { /* no Resource Timing: the warning still comes, counted from the last answer to Stay */ }
    const signIn = () => { window.location.href = status.sso_login_url || '/login'; };
    idleTimer = setInterval(async () => {
      const left = idle - (Date.now() - last) / 1000;
      if (left <= 0) { clearInterval(idleTimer); signIn(); return; }
      if (status.expires_in && !endWarned && (endAt - Date.now()) / 1000 <= END_WARN_S) {
        endWarned = true;
        notice({ title: 'Your session ends soon', body: `This session ends at ${new Date(endAt).toLocaleTimeString()} whatever you do (the server's limit for one sign-in). Save your work; you will sign in again.` });
      }
      if (left <= IDLE_WARN_S && !asking) {
        asking = true;
        const stay = await ask({ title: 'Still there?', body: `You will be signed out in about ${Math.max(1, Math.round(left / 60))} minute(s) because nothing has happened on this page. Stay signed in?`, okLabel: 'Stay signed in', cancelLabel: 'Sign out' });
        asking = false;
        if (stay) {
          try { const r = await fetch('/api/auth/status', { credentials: 'same-origin', cache: 'no-store' }); const s = r.ok ? await r.json() : null; if (s && s.unlocked) touch(); else signIn(); } catch (e) { /* the next tick decides */ }
        } else {
          try { await fetch(status.logout_url || '/api/auth/logout', { method: 'POST', credentials: 'same-origin' }); } catch (e) { /* gone anyway */ }
          signIn();
        }
      }
    }, 10000);
  }
  window.__dlpIdleWatch = startIdleWatch;

  function loadSsoStatus() {
    fetch('/api/auth/status', { credentials: 'same-origin' }).then(r => r.ok ? r.json() : null).then(s => { ssoBar(s); startIdleWatch(s); }).catch(() => {});
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', loadSsoStatus); else loadSsoStatus();

  // Under SSO there is no token to paste: send the person to sign in instead.
  async function unlockOrSignIn(message) {
    if (ssoStatus && ssoStatus.sso) { window.location.href = ssoStatus.sso_login_url || '/api/auth/sso/login'; return null; }
    return unlock(message);
  }

  window.dlpDialog = { unlock, notice, phrase, ask };
  window.__dlpUnlockDialog = unlockOrSignIn;

  // Many pages still call the browser's own alert(), confirm() and prompt().
  // An embedded browser can refuse them by throwing ("not supported"), which
  // killed the button that asked (nothing happened, nothing said). Each is
  // wrapped once: the browser's box is still used when it works; when it is
  // refused, the message is shown in the app's own dialog instead, and a
  // question nobody could answer reads as "no" (confirm -> false, prompt ->
  // null), so nothing is changed without an answer. Never an exception.
  ['alert', 'confirm', 'prompt'].forEach(name => {
    const orig = window[name];
    if (typeof orig !== 'function' || orig.__dlpGuarded) return;
    const guarded = function (message, ...rest) {
      try { return orig.call(window, message, ...rest); }
      catch (e) {
        if (supported()) {
          const text = String(message == null ? '' : message);
          if (name === 'alert') notice({ title: 'Notice', body: text, pre: true });
          else notice({ title: 'This browser could not ask', tone: 'bad', pre: true,
                        body: text, fix: 'Nothing was done: this browser refused its own question box. Open the app in Chrome or Edge to answer it.' });
        }
        return name === 'confirm' ? false : name === 'prompt' ? null : undefined;
      }
    };
    guarded.__dlpGuarded = true;
    try { window[name] = guarded; } catch (e) { /* a locked-down window: leave the browser's own */ }
  });
})();
