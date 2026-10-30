// Report tabs follow the assessment page's theme: the same saved
// preference (localStorage 'zassess_theme', shared because the tabs are
// same-origin), the same OS fallback, the same toggle button, and a live
// follow when the theme is switched in another tab.
(function () {
  function apply(theme, save) {
    document.body.classList.toggle('theme-light', theme === 'light');
    if (save) { try { localStorage.setItem('zassess_theme', theme); } catch (e) { /* private mode */ } }
    const btn = document.getElementById('themeToggleBtn');
    if (btn) {
      btn.textContent = theme === 'light' ? '🌙 Dark mode' : '☀ Light mode';
      btn.setAttribute('aria-label', theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode');
    }
  }
  function current() {
    let saved = null;
    try { saved = localStorage.getItem('zassess_theme'); } catch (e) { /* ignore */ }
    if (saved === 'light' || saved === 'dark') return saved;
    return (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
  }
  function init() {
    apply(current(), false);
    // The toggle belongs to pages styled by the app's own stylesheet; a
    // self-contained reference page keeps its own look.
    if (!document.getElementById('themeToggleBtn') && document.querySelector('link[href="/app.css"]')) {
      const btn = document.createElement('button');
      btn.id = 'themeToggleBtn';
      btn.type = 'button';
      btn.style.cssText = 'position:fixed;bottom:0.75rem;right:0.75rem;z-index:800;background:var(--card-solid, var(--well));border:1px solid var(--border);border-radius:8px;padding:0.45rem 0.7rem;font-size:0.75rem;color:var(--text);cursor:pointer;';
      btn.addEventListener('click', () => apply(document.body.classList.contains('theme-light') ? 'dark' : 'light', true));
      document.body.appendChild(btn);
      apply(current(), false);
    }
  }
  window.addEventListener('storage', e => { if (e.key === 'zassess_theme') apply(current(), false); });
  if (document.body) init(); else document.addEventListener('DOMContentLoaded', init);
})();

// ── UI token ──────────────────────────────────────────────────────────
// Every page shares this: if the server answers 401 "token required", ask
// for the token once (it is in ui_token.txt next to the app, or on the
// server's log or terminal), unlock, and retry the request.
(function () {
  if (window.__dlpAuthWrapped) return;
  window.__dlpAuthWrapped = true;
  const realFetch = window.fetch.bind(window);
  let asking = null;
  // The app's own dialog (ui_auth.js, loaded before this file) asks for the
  // token; the browser prompt is the fallback, guarded so an unsupported
  // prompt() reads as "cancelled" and this wrapper never throws.
  let askFailed = null;   // the last reason the browser could not ask at all
  async function askForToken(message) {
    askFailed = null;
    try {
      if (window.__dlpUnlockDialog) return await window.__dlpUnlockDialog(message);
      return window.prompt((message || 'This server asks for its UI token.') + '\n\nIt is in ui_token.txt next to the app (also in server.log, or the terminal window that runs the app). Paste it here:');
    } catch (e) { askFailed = String(e && e.message || e); return null; }
  }
  // A cancelled unlock is respected for a while; a deliberate action asks
  // again through window.__dlpAskAgain().
  let declinedAt = 0;
  const DECLINE_QUIET_MS = 30000;
  const UNLOCK_TRIES = 3;
  const WRONG_TOKEN = 'That token was not accepted. Copy it again from ui_token.txt next to the app (or the window that runs the app), exactly as it is.';
  window.__dlpAskAgain = () => { declinedAt = 0; };
  async function unlock(message) {
    if (asking) return asking;
    if (Date.now() - declinedAt < DECLINE_QUIET_MS) return false;
    asking = (async () => {
      // A token the server refuses is asked for again with the reason (a
      // mistyped or stale paste), at most three times; then quiet, as a cancel.
      let msg = message;
      for (let attempt = 0; attempt < UNLOCK_TRIES; attempt++) {
        const t = await askForToken(msg);
        if (t === null || t === undefined || !String(t).trim()) { declinedAt = Date.now(); return false; }
        const r = await realFetch('/api/auth/unlock', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: String(t).trim() }) });
        if (r.ok) return true;
        if (r.status !== 401) return false;
        msg = WRONG_TOKEN;
      }
      declinedAt = Date.now();
      return false;
    })();
    try { return await asking; } catch (e) { return false; } finally { asking = null; }
  }
  window.fetch = async function (input, init) {
    let r = await realFetch(input, init);
    if (r.status === 401) {
      let body = null;
      try { body = await r.clone().json(); } catch (e) { /* not json */ }
      if (body && body.token_required) {
        const ok = await unlock(body.detail);
        if (ok) r = await realFetch(input, init);
        else { try { r.dlpTokenRequired = true; if (askFailed) r.dlpDialogUnavailable = askFailed; } catch (e) {} }
      }
    }
    return r;
  };
  window.__dlpUnlock = unlock;
})();

// ── Overview first ────────────────────────────────────────────────────
// A report page's hero paragraph is often the whole explanation. The
// first sentence stays on screen; the rest folds behind a "More" button
// (a real button: aria-expanded, keyboard, screen reader), so the useful
// content is one line down instead of a paragraph down.
(function () {
  const MIN_CHARS = 240;
  function fold() {
    const p = document.querySelector('.rp-hero > p');
    if (!p || p.dataset.folded || p.querySelector('*')) return;
    const text = p.textContent.replace(/\s+/g, ' ').trim();
    if (text.length < MIN_CHARS) return;
    // Cut at the first sentence end; a one-sentence paragraph is cut at its
    // first colon or semicolon, else at the first comma after ~90 characters.
    const m = text.match(/^(.{40,}?[.!?])\s+(\S.*)$/) || text.match(/^(.{60,}?[:;])\s+(\S.*)$/) || text.match(/^(.{90,}?),\s+(\S.*)$/);
    if (!m || m[2].length < 60) return;
    const cutMid = !/[.!?]$/.test(m[1]);
    p.dataset.folded = '1';
    p.textContent = '';
    const lead = document.createElement('span'); lead.textContent = m[1] + (cutMid ? ' … ' : ' ');
    const more = document.createElement('span'); more.id = 'rpHeroMore'; more.textContent = m[2] + ' '; more.hidden = true;
    const btn = document.createElement('button');
    btn.type = 'button'; btn.className = 'rp-more'; btn.textContent = 'More'; btn.setAttribute('aria-expanded', 'false'); btn.setAttribute('aria-controls', 'rpHeroMore');
    btn.addEventListener('click', () => { const open = more.hidden; more.hidden = !open; btn.setAttribute('aria-expanded', String(open)); btn.textContent = open ? 'Less' : 'More'; });
    p.append(lead, more, btn);
    if (!document.getElementById('rpMoreStyle')) {
      const st = document.createElement('style'); st.id = 'rpMoreStyle';
      st.textContent = '.rp-more{background:none;border:1px solid var(--border,#334155);border-radius:6px;color:var(--accent,#60a5fa);cursor:pointer;font:inherit;font-size:0.85em;padding:0 0.45rem;line-height:1.5;vertical-align:baseline}.rp-more:focus-visible{outline:2px solid var(--accent,#60a5fa);outline-offset:2px}';
      document.head.appendChild(st);
    }
  }
  if (document.body) fold(); else document.addEventListener('DOMContentLoaded', fold);
  window.__dlpFoldIntro = fold;
})();

// ── Back to the main page ─────────────────────────────────────────────
// Every tab the app opens can return to the assessment page: a link with
// href="/" (the report bars have one) goes back to the tab that opened
// this one and closes this tab; a page without such a link gets a fixed
// "Back to the assessment" button. With no opener left, the link simply
// loads the main page.
(function () {
  function goHome(e) {
    if (e) e.preventDefault();
    const o = window.opener;
    if (o && !o.closed) {
      try { o.focus(); } catch (err) { /* cross-window */ }
      window.close();
      setTimeout(() => { if (!window.closed) location.href = '/'; }, 300);
      return;
    }
    location.href = '/';
  }
  function init() {
    const links = Array.from(document.querySelectorAll('a[href="/"]'));
    links.forEach(a => { a.addEventListener('click', goHome); if (!a.title) a.title = 'Back to the assessment page'; });
    if (!links.length && !document.getElementById('backHomeBtn')) {
      const b = document.createElement('a');
      b.id = 'backHomeBtn'; b.href = '/'; b.textContent = '← Back to the assessment';
      b.setAttribute('aria-label', 'Back to the assessment page');
      // Bottom-left, clear of the page's own header (the reference pages
      // put their brand top-left), with literal fallbacks: those pages do
      // not define the app's tokens.
      b.style.cssText = 'position:fixed;bottom:0.9rem;left:0.9rem;z-index:2147483000;min-height:36px;display:inline-flex;align-items:center;padding:0 0.9rem;border-radius:10px;background:var(--btn, #0071e3);color:#fff;font:600 13px system-ui,-apple-system,"Segoe UI",sans-serif;text-decoration:none;box-shadow:0 4px 14px rgba(0,0,0,0.25);';
      b.addEventListener('click', goHome);
      document.body.appendChild(b);
    }
  }
  if (document.body) init(); else document.addEventListener('DOMContentLoaded', init);
  window.__dlpGoHome = goHome;
})();

// What's new (static/whats_new.js): the * after each new feature's label,
// on every page that loads this file (the home page gets it through
// GUI_ADDONS). Same origin, so the CSP ('self') allows it.
(function () {
  if (window.WhatsNew || document.querySelector('script[src^="/static/whats_new.js"]')) return;
  const s = document.createElement('script');
  s.src = '/static/whats_new.js';
  (document.head || document.documentElement).appendChild(s);
})();

// Reduced motion covers scripted scrolling too (WCAG 2.3.3): Chromium
// animates scrollIntoView / scrollTo({ behavior: 'smooth' }) even when the
// user asked the system for reduced motion, so while that preference is on
// every smooth scroll the page asks for becomes an instant one.
(function () {
  if (window.__dlpCalmScroll || !window.matchMedia) return;
  const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
  const calm = o => (mq.matches && o && typeof o === 'object' && o.behavior === 'smooth') ? Object.assign({}, o, { behavior: 'auto' }) : o;
  const wrap = (obj, name) => {
    const orig = obj && obj[name];
    if (typeof orig !== 'function') return;
    obj[name] = function (first, ...rest) { return orig.call(this, calm(first), ...rest); };
  };
  ['scrollIntoView', 'scroll', 'scrollTo', 'scrollBy'].forEach(n => wrap(Element.prototype, n));
  ['scroll', 'scrollTo', 'scrollBy'].forEach(n => wrap(window, n));
  window.__dlpCalmScroll = calm;
})();
