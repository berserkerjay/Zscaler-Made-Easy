/* Runs before the reference's scripts. A matching parent origin, window,
 * slug and per-navigation token are all required at the receiving end. */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else api.start(root);
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';
  function contentReady(win, slug) {
    const doc = win.document;
    if (slug === 'portfolio-map') return typeof win.__mapShow === 'function' &&
      !!doc.querySelector('nav.sections') && !!doc.querySelector('section.visible');
    if (slug === 'copilot-readiness') {
      const matrix = doc.getElementById('matrix');
      return typeof win.switchTab === 'function' && typeof win.renderMatrix === 'function' &&
        !!matrix && matrix.children.length > 0 && !!doc.getElementById('tab-framework');
    }
    return false;
  }
  function start(win) {
    const meta = win.document.querySelector('meta[name="dlp-reference-embed"]');
    const slug = meta && meta.content;
    const token = new URL(win.location.href).searchParams.get('embed_token');
    if (!['portfolio-map','copilot-readiness'].includes(slug) || !token || win.parent === win) return null;
    let failed = false, sent = null;
    function publish(state) {
      if (sent === state) return;
      sent = state;
      win.parent.postMessage({type:'dlp-reference-state', slug, token, state}, win.location.origin);
    }
    function error(event) {
      // Fonts/images may fail independently; script/runtime failures matter.
      if (event && !event.error && event.target && event.target !== win && event.target.tagName !== 'SCRIPT') return;
      failed = true; publish('error');
    }
    win.addEventListener('error', error, true);
    win.addEventListener('unhandledrejection', error);
    function ready() {
      if (failed) return;
      if (contentReady(win, slug)) publish('ready');
      else { failed = true; publish('error'); }
    }
    if (win.document.readyState === 'loading') win.document.addEventListener('DOMContentLoaded', ready, {once:true});
    else ready();
    return Object.freeze({ready, error});
  }
  return Object.freeze({contentReady, start});
});
