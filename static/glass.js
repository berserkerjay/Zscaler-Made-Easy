// ── Glass effect (static/glass.css): the per-viewer switch and the lens ──
// Loaded in <head>, before the page is drawn, so a viewer who turned the
// effect off never sees it flash on: the choice is a class on <html>
// ("glass-off"), read from this browser's localStorage. The default is on.
// The switch itself is "Glass effect" in Advanced settings (#advGlass); a
// change there applies at once, here and in every other open tab.
//
// The lens: a soft highlight that follows the pointer over glass panels and
// buttons. One passive pointermove listener, at most one update per frame
// (requestAnimationFrame), two CSS variables on the one element under the
// pointer. Off under prefers-reduced-motion, reduced transparency, more
// contrast, forced colours, for touch (no pointer to follow) and when the effect is off.
//
// The backdrop's drift is pure CSS (glass.css). The one thing it needs from
// here: while the tab is hidden, html.glass-still pauses it (one
// visibilitychange listener; nothing runs per frame for it).
//
// Blur fits the window: a card or dialog card is blurred only while it is no
// taller than the window (class glass-fit). A ResizeObserver keeps that
// current; a MutationObserver (debounced) picks up cards added later. A card
// not yet measured stays unblurred, the safe side.
// No library, no external asset, nothing from the server.
(function () {
  'use strict';
  if (window.dlpGlass) return;
  var KEY = 'zassess_glass';
  var root = document.documentElement;
  var LENS = '.rp-card, .container .card, .xp-details, .db-tile, .db-pillar, .df-stat, .bp-card, .op-kind, .op-block, .rp-btn, .container .btn-ghost, .rp-more, .rp-tabs [role="tab"], .fa-tabs [role="tab"]';
  var QUIET = ['(prefers-reduced-motion: reduce)', '(prefers-reduced-transparency: reduce)', '(prefers-contrast: more)', '(forced-colors: active)'];

  function read() {
    try { return localStorage.getItem(KEY); } catch (e) { return null; }   // private mode, blocked storage
  }
  function write(on) {
    try { localStorage.setItem(KEY, on ? 'on' : 'off'); } catch (e) { /* the choice lasts for this page only */ }
  }
  function apply(on) { root.classList.toggle('glass-off', !on); }
  function enabled() { return !root.classList.contains('glass-off'); }
  function media(q) { try { return !!(window.matchMedia && window.matchMedia(q).matches); } catch (e) { return false; } }
  // What the system asks for: any of these keeps every surface solid whatever the switch says (glass.css).
  function systemSolid() { return media('(prefers-reduced-transparency: reduce)') || media('(prefers-contrast: more)') || media('(forced-colors: active)'); }

  apply(read() !== 'off');

  // ── The drift pauses while the tab is hidden ──
  function still() { root.classList.toggle('glass-still', document.visibilityState === 'hidden'); }
  still();
  document.addEventListener('visibilitychange', still);

  // ── While the page scrolls ──
  // Every blurred layer is drawn again on each frame its backdrop moves; on a
  // computer without a graphics card (or with two slow cores) the blur of the
  // cards and the hero in the page flow, re-drawn on every scrolled frame,
  // brought the page down to a few frames a second. Behind those there is
  // only the soft colour backdrop, which looks the same unblurred, so while
  // the page (or any scrolling box in it) scrolls, html.glass-scrolling turns
  // their blur off and holds the drift; floating bars, the sidebar and
  // dialogs keep theirs (what scrolls under them is what the blur is for).
  // One passive scroll listener (capture, so a scrolling box counts too): the
  // class is set once per gesture and cleared 180 ms after the last scroll
  // event. Nothing runs per frame.
  var scrollTimer = 0;
  function scrolled() {
    clearTimeout(scrollTimer);
    scrollTimer = setTimeout(function () { scrollTimer = 0; root.classList.remove('glass-scrolling'); }, 180);
    if (!root.classList.contains('glass-scrolling')) root.classList.add('glass-scrolling');
  }
  document.addEventListener('scroll', scrolled, { passive: true, capture: true });

  // ── The lens ──
  var lensTarget = null, lastEvent = null, frame = 0;
  function lensAllowed() {
    if (!enabled()) return false;
    for (var i = 0; i < QUIET.length; i++) if (media(QUIET[i])) return false;
    return true;
  }
  var allowed = lensAllowed();
  function clearLens() {
    if (lensTarget) { lensTarget.style.removeProperty('--glass-x'); lensTarget.style.removeProperty('--glass-y'); lensTarget = null; }
  }
  function draw() {
    frame = 0;
    var e = lastEvent; lastEvent = null;
    if (!e || !allowed) { clearLens(); return; }
    var t = e.target && e.target.closest ? e.target.closest(LENS) : null;
    if (t !== lensTarget) clearLens();
    if (!t) return;
    var r = t.getBoundingClientRect();
    t.style.setProperty('--glass-x', Math.round(e.clientX - r.left) + 'px');
    t.style.setProperty('--glass-y', Math.round(e.clientY - r.top) + 'px');
    lensTarget = t;
  }
  function onMove(e) {
    if (!allowed || e.pointerType === 'touch') return;
    lastEvent = e;
    if (!frame) frame = requestAnimationFrame(draw);
  }
  function recheck() { allowed = lensAllowed(); if (!allowed) clearLens(); }
  document.addEventListener('pointermove', onMove, { passive: true });
  root.addEventListener('pointerleave', clearLens, { passive: true });
  QUIET.forEach(function (q) {
    try { var m = window.matchMedia(q); if (m.addEventListener) m.addEventListener('change', function () { recheck(); sync(); }); } catch (e) { /* old browser */ }
  });

  // ── Blur fits the window ──
  var FIT = '.rp-card, .container .card, .xp-details, .db-modal-card, [id$="Modal"] > div';
  var seen = typeof WeakSet === 'function' ? new WeakSet() : null, ro = null, scanTimer = 0, fitTimer = 0;
  function fitOne(el) {
    var h = el.getBoundingClientRect().height;
    el.classList.toggle('glass-fit', h > 0 && h <= window.innerHeight);
  }
  function scan() {
    scanTimer = 0;
    if (!ro) return;
    var els = document.querySelectorAll(FIT);
    for (var i = 0; i < els.length; i++) if (!seen.has(els[i])) { seen.add(els[i]); ro.observe(els[i]); }
  }
  function refit() {   // the window's height changed: every card again (debounced, not per frame)
    fitTimer = 0;
    var els = document.querySelectorAll(FIT);
    for (var i = 0; i < els.length; i++) fitOne(els[i]);
  }
  if (seen && typeof window.ResizeObserver === 'function') {
    ro = new window.ResizeObserver(function (entries) {
      for (var i = 0; i < entries.length; i++) {
        var t = entries[i].target;
        if (t.isConnected) fitOne(t); else { ro.unobserve(t); seen.delete(t); }   // removed from the page: let it go
      }
    });
    window.addEventListener('resize', function () { if (!fitTimer) fitTimer = setTimeout(refit, 120); }, { passive: true });
    if (typeof window.MutationObserver === 'function') {
      new window.MutationObserver(function () { if (!scanTimer) scanTimer = setTimeout(scan, 200); }).observe(root, { childList: true, subtree: true });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', scan); else scan();
  }

  // ── The switch in Advanced settings ──
  function sync() {
    var box = document.getElementById('advGlass');
    if (box) box.checked = enabled();
    var note = document.getElementById('advGlassNote');
    if (note) {
      note.textContent = !enabled() ? 'Off: every surface is solid on this browser.'
        : systemSolid() ? 'On, but your system asks for less transparency or more contrast, so surfaces stay solid.'
        : 'On: chrome, cards and buttons are translucent glass on this browser.';
    }
  }
  function set(on) {
    apply(!!on); write(!!on); recheck(); sync();
    try { window.dispatchEvent(new CustomEvent('dlp:glass', { detail: { on: !!on } })); } catch (e) { /* old browser */ }
  }
  function wire() {
    var box = document.getElementById('advGlass');
    if (box && !box.dataset.glassWired) {
      box.dataset.glassWired = '1';
      box.addEventListener('change', function () { set(box.checked); });
    }
    sync();
  }
  // Another tab changed it: follow.
  window.addEventListener('storage', function (e) { if (e.key === KEY) { apply(e.newValue !== 'off'); recheck(); sync(); } });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire); else wire();

  window.dlpGlass = { enabled: enabled, set: set, systemSolid: systemSolid, KEY: KEY };
})();
