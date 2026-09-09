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
