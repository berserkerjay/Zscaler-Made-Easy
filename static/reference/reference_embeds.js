/* Same-origin reference loading. No tenant requests or cross-module state. */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else { root.ReferenceEmbeds = api; api.mount(root); }
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';
  const definitions = Object.freeze({
    'portfolio-map': Object.freeze({frameId:'mapFrame', label:'Portfolio Architecture'}),
    'copilot-readiness': Object.freeze({frameId:'copilotFrame', label:'Copilot Readiness'})
  });
  let sequence = 0;
  function newToken() {
    const bytes = new Uint32Array(4);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(bytes);
      return Array.from(bytes, x => x.toString(16).padStart(8, '0')).join('');
    }
    // This is a navigation correlation token, never an authentication secret.
    return 'navigation-' + Date.now().toString(36) + '-' + (++sequence);
  }
  function createController(options) {
    if (!options || !definitions[options.slug]) throw new Error('Unknown reference');
    const {slug, frame} = options;
    const origin = new URL(options.origin).origin;
    if (!/^https?:/.test(origin)) throw new Error('An HTTP(S) app origin is required');
    const schedule = options.setTimeout || setTimeout;
    const cancel = options.clearTimeout || clearTimeout;
    const tokenFactory = options.tokenFactory || newToken;
    const changed = options.onChange || function () {};
    const timeoutMs = options.timeoutMs === undefined ? 15000 : options.timeoutMs;
    let state = 'idle', token = null, timer = null, generation = 0;
    function snapshot() { return Object.freeze({slug, state, token, generation}); }
    function clearTimer() { if (timer !== null) cancel(timer); timer = null; }
    function transition(next) { state = next; changed(snapshot()); }
    function fail(expectedToken) {
      if (state === 'destroyed' || expectedToken !== token || !['loading','ready'].includes(state)) return false;
      clearTimer(); transition('error'); return true;
    }
    function load(force) {
      if (state === 'destroyed' || (!force && (state === 'loading' || state === 'ready'))) return false;
      clearTimer(); generation += 1; token = String(tokenFactory());
      const current = token;
      transition('loading');
      timer = schedule(() => { if (state === 'loading') fail(current); }, timeoutMs);
      try {
        const url = new URL('/reference/embed/' + slug, origin);
        url.searchParams.set('embed_token', current);
        frame.src = url.href;
      } catch (error) { fail(current); }
      return true;
    }
    function receive(event) {
      if (state === 'destroyed' || !event || event.origin !== origin || event.source !== frame.contentWindow) return false;
      const data = event.data;
      if (!data || typeof data !== 'object' || data.type !== 'dlp-reference-state' || data.slug !== slug || !token || data.token !== token) return false;
      if (data.state === 'error') return fail(token);
      if (data.state !== 'ready' || state !== 'loading') return false;
      clearTimer(); transition('ready'); return true;
    }
    function destroy() { if (state === 'destroyed') return; clearTimer(); token = null; transition('destroyed'); }
    return Object.freeze({load, receive, fail, destroy, snapshot});
  }
  const mounted = new Map();
  function mount(win) {
    if (!win || !win.document) return;
    Object.entries(definitions).forEach(([slug, def]) => {
      if (mounted.has(slug)) return;
      const frame = win.document.getElementById(def.frameId);
      const status = win.document.getElementById(def.frameId + 'Status');
      const retry = win.document.getElementById(def.frameId + 'Retry');
      if (!frame || !status || !retry) return;
      const controller = createController({slug, frame, origin:win.location.origin,
        onChange: ({state}) => {
          frame.dataset.state = state;
          frame.setAttribute('aria-busy', state === 'loading' ? 'true' : 'false');
          retry.hidden = state !== 'error';
          status.textContent = state === 'loading' ? 'Loading ' + def.label + '…' :
            state === 'ready' ? def.label + ' loaded.' : state === 'error' ?
            'Could not load ' + def.label + '. Check that this app is unlocked, then retry.' : '';
        }});
      const receive = event => controller.receive(event);
      const retryClick = () => controller.load(true);
      win.addEventListener('message', receive);
      retry.addEventListener('click', retryClick);
      // A frame's load event is not proof of success (error documents also
      // fire it). Only the child handshake can move loading -> ready.
      const dispose = () => {
        controller.destroy(); win.removeEventListener('message', receive);
        retry.removeEventListener('click', retryClick); mounted.delete(slug);
      };
      mounted.set(slug, {controller, dispose});
    });
    // pagehide with persisted=true is the back/forward cache, not teardown.
    if (!win.__referenceEmbedsLifecycle) {
      win.__referenceEmbedsLifecycle = true;
      win.addEventListener('pagehide', event => {
        if (!event.persisted) Array.from(mounted.values()).forEach(item => item.dispose());
      });
      win.addEventListener('pageshow', () => mount(win));
    }
  }
  function open(slug) { const item = mounted.get(slug); return item ? item.controller.load(false) : false; }
  return Object.freeze({definitions, createController, mount, open});
});
