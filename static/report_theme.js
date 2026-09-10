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
    if (!document.getElementById('themeToggleBtn')) {
      const btn = document.createElement('button');
      btn.id = 'themeToggleBtn';
      btn.type = 'button';
      btn.style.cssText = 'position:fixed;bottom:0.75rem;right:0.75rem;z-index:800;background:rgba(15,23,42,0.85);border:1px solid var(--border);border-radius:8px;padding:0.45rem 0.7rem;font-size:0.75rem;color:var(--text);cursor:pointer;backdrop-filter:blur(6px);';
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
// server console), unlock, and retry the request.
(function () {
  if (window.__dlpAuthWrapped) return;
  window.__dlpAuthWrapped = true;
  const realFetch = window.fetch.bind(window);
  let asking = null;
  async function unlock(message) {
    if (asking) return asking;
    asking = (async () => {
      const t = window.prompt((message || 'This server asks for its UI token.') + '\n\nIt is in ui_token.txt next to the app (also printed on the server console). Paste it here:');
      if (t === null) return false;
      const r = await realFetch('/api/auth/unlock', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: t.trim() }) });
      return r.ok;
    })();
    try { return await asking; } finally { asking = null; }
  }
  window.fetch = async function (input, init) {
    let r = await realFetch(input, init);
    if (r.status === 401) {
      let body = null;
      try { body = await r.clone().json(); } catch (e) { /* not json */ }
      if (body && body.token_required) {
        const ok = await unlock(body.detail);
        if (ok) r = await realFetch(input, init);
      }
    }
    return r;
  };
  window.__dlpUnlock = unlock;
})();
