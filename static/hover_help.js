// ── Help on hover ─────────────────────────────────────────────────────
// One pop-up for every control on every page: what it does, what input it
// expects, and whether it reads or changes the tenant. The words live in
// help_catalog.js (window.HELP_CATALOG), keyed per page by CSS selector;
// this file only finds the controls, wires them and shows the words.
//
// WCAG 2.2: the pop-up opens on hover and on keyboard focus (1.4.13), a
// long press or the ⓘ target opens it on touch (2.5.8: the target is 28px),
// Esc closes it without moving focus, the pointer can move onto it without
// it closing, and it stays until Esc or until focus and hover leave. Each
// control's aria-describedby points at the same words (1.3.1, 4.1.2). The
// pop-up is placed beside the control, never over it, and inside the
// viewport down to 320px. Every word is set with textContent, never HTML.
// A native title on a described control is taken off (two tooltips would
// stack) and kept as the pop-up's "Right now" line when it says more.
(function () {
  'use strict';
  if (window.HoverHelp) return;

  // What counts as a control: everything a person can press, type into or
  // pick. Links count too (the catalogue explains where they go).
  const CONTROL = [
    'button', 'a[href]', 'input:not([type="hidden"])', 'select', 'textarea', 'summary',
    '[role="button"]', '[role="tab"]', '[role="checkbox"]', '[role="switch"]', '[role="radio"]',
    '[role="menuitem"]', '[role="menuitemcheckbox"]', '[role="menuitemradio"]', '[role="option"][tabindex]',
    '[contenteditable="true"]',
  ].join(',');
  const EFFECTS = {
    local: 'Stays in this app. It does not touch your tenant.',
    read: 'Reads your tenant. It changes nothing there.',
    write: 'Can change your tenant. It needs write mode, a named assessor and a typed confirmation first.',
    download: 'Saves a file on this computer. It changes nothing in your tenant.',
    nav: 'Opens a page. It changes nothing by itself.',
  };
  const HOVER_DELAY = 300;   // ms before a hover opens it (moving across a toolbar stays quiet)
  const LEAVE_GRACE = 200;   // ms to move the pointer from the control onto the pop-up
  const LONG_PRESS = 550;    // ms of a touch before it counts as a long press
  const GAP = 6;             // px between the control and the pop-up
  const EDGE = 8;            // px kept free at the viewport's edges

  const norm = s => String(s == null ? '' : s).replace(/\s+/g, ' ').trim();
  const clock = { set: (f, ms) => window.setTimeout(f, ms), clear: id => window.clearTimeout(id) };

  // ── The catalogue ───────────────────────────────────────────────────
  function pageKey() {
    const forced = document.documentElement.getAttribute('data-hh-page');
    if (forced) return forced;
    const p = (location.pathname || '/').replace(/\/+$/, '');
    return p || '/';
  }
  let compiled = null;
  function catalogue() {
    if (compiled && compiled.page === pageKey()) return compiled;
    const cat = window.HELP_CATALOG || {};
    const pages = cat.pages || {};
    const list = [];
    const add = (group, entries) => {
      Object.keys(entries || {}).forEach(sel => {
        const e = entries[sel];
        if (e && typeof e === 'object') list.push({ group, sel, e, idx: list.length });
      });
    };
    add(pageKey(), pages[pageKey()]);
    add('*', pages['*']);
    compiled = { page: pageKey(), list };
    return compiled;
  }
  function entryFor(el) {
    for (const item of catalogue().list) {
      let hit = false;
      try { hit = el.matches(item.sel); } catch (err) { hit = false; }
      if (hit) return item;
    }
    return null;
  }

  // ── Which elements are controls ─────────────────────────────────────
  function ours(el) { return !!(el.closest && el.closest('[data-hh-ui]')); }
  function isControl(el) {
    if (!el || el.nodeType !== 1 || ours(el)) return false;
    try { return el.matches(CONTROL); } catch (err) { return false; }
  }
  function isVisible(el) {
    if (!el.isConnected) return false;
    const r = el.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) return false;
    const cs = getComputedStyle(el);
    return cs.visibility !== 'hidden' && cs.display !== 'none' && !el.closest('[hidden], [inert]');
  }
  function controls(root) {
    return Array.from((root || document).querySelectorAll(CONTROL)).filter(el => !ours(el));
  }
  function controlFrom(node) {
    let el = node && node.nodeType === 1 ? node : node && node.parentElement;
    while (el && el !== document.body) {
      if (isControl(el)) return el;
      el = el.parentElement;
    }
    return null;
  }
  // A short CSS selector that names the control, for the coverage report.
  function describe(el) {
    if (el.id) return '#' + el.id;
    let s = el.tagName.toLowerCase();
    ['type', 'name', 'role', 'data-act', 'data-action', 'data-tab', 'data-tile', 'onclick'].forEach(a => {
      const v = el.getAttribute(a);
      if (v) s += `[${a}="${v.slice(0, 60).replace(/"/g, '\\"')}"]`;
    });
    if (el.classList.length) s += '.' + Array.from(el.classList).slice(0, 3).join('.');
    const host = el.parentElement && el.parentElement.closest('[id]');
    const text = norm(el.getAttribute('aria-label') || el.textContent).slice(0, 40);
    return (host ? '#' + host.id + ' ' : '') + s + (text ? ` "${text}"` : '');
  }

  // ── Descriptions for screen readers ─────────────────────────────────
  // One hidden description per catalogue entry (per open dialog, so a
  // modal's inert background never hides it), shared by every control the
  // entry matches; a control with its own "Right now" line gets its own.
  let serial = 0;
  function descHost(el) {
    const dlg = el.closest('dialog');
    const owner = dlg || document.body;
    let host = Array.from(owner.children).find(c => c.classList && c.classList.contains('hh-descs'));
    if (!host) {
      host = document.createElement('div');
      host.className = 'hh-descs';
      host.hidden = true;
      host.setAttribute('data-hh-ui', '');
      host.dataset.hhScope = String(++serial);
      owner.appendChild(host);
    }
    return host;
  }
  function sentence(item, note) {
    const e = item.e;
    const parts = [norm(e.what), 'Input: ' + norm(e.input)];
    if (EFFECTS[e.effect]) parts.push(EFFECTS[e.effect]);
    if (note) parts.push('Right now: ' + note);
    return parts.join(' ');
  }
  function descFor(el, item, note) {
    const host = descHost(el);
    const id = note ? 'hh-n-' + (++serial) : `hh-d-${item.idx}-${host.dataset.hhScope}`;
    let span = note ? null : document.getElementById(id);
    if (!span) {
      span = document.createElement('span');
      span.id = id;
      host.appendChild(span);
    }
    span.textContent = sentence(item, note);
    return id;
  }
  function noteOf(el, item) {
    const t = norm(el.getAttribute('data-hh-title'));
    if (!t) return '';
    const known = norm(item.e.what + ' ' + item.e.input).toLowerCase();
    return known.includes(t.toLowerCase()) ? '' : t;
  }
  function wire(el) {
    if (!isControl(el)) return null;
    const item = entryFor(el);
    if (!item) return null;
    // A native title would open a second tooltip: keep its words, drop it.
    if (el.hasAttribute('title')) {
      el.setAttribute('data-hh-title', el.getAttribute('title'));
      el.removeAttribute('title');
    }
    const note = noteOf(el, item);
    const mine = (el.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean);
    const others = mine.filter(id => !/^hh-[dn]-/.test(id));
    const old = mine.find(id => /^hh-n-/.test(id));
    if (old && note) { const s = document.getElementById(old); if (s) s.remove(); }
    const id = descFor(el, item, note);
    el.setAttribute('aria-describedby', others.concat(id).join(' '));
    el.setAttribute('data-hh', item.sel);
    return item;
  }
  let pending = false;
  function scan() {
    pending = false;
    controls(document).forEach(el => {
      const sig = (el.getAttribute('data-hh-title') || '') + '|' + (el.getAttribute('title') || '');
      if (el.__hhSig === sig && el.hasAttribute('data-hh')) return;
      el.__hhSig = sig;
      wire(el);
      el.__hhSig = (el.getAttribute('data-hh-title') || '') + '|' + (el.getAttribute('title') || '');
    });
  }
  function soon() {
    if (pending) return;
    pending = true;
    (window.requestAnimationFrame || (f => clock.set(f, 16)))(scan);
  }

  // ── The pop-up ──────────────────────────────────────────────────────
  let tip = null, info = null, current = null, dismissed = null;
  let hoverTimer = null, leaveTimer = null, pressTimer = null;
  const hovering = { control: false, tip: false };
  function make(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function build() {
    if (tip && tip.isConnected) return tip;
    tip = make('div', 'hh-tip');
    tip.id = 'hhTip';
    tip.setAttribute('role', 'tooltip');
    tip.setAttribute('data-hh-ui', '');
    tip.hidden = true;
    if ('popover' in tip) tip.setAttribute('popover', 'manual');
    tip.addEventListener('mouseenter', () => { hovering.tip = true; clock.clear(leaveTimer); });
    tip.addEventListener('mouseleave', () => { hovering.tip = false; leaveSoon(); });
    document.body.appendChild(tip);
    return tip;
  }
  function fill(el, item) {
    const e = item.e;
    const note = noteOf(el, item);
    const rows = [make('p', 'hh-what', norm(e.what))];
    const inp = make('p', 'hh-input');
    inp.append(make('strong', null, 'Input: '), document.createTextNode(norm(e.input)));
    rows.push(inp);
    if (EFFECTS[e.effect]) rows.push(make('p', 'hh-effect hh-' + e.effect, EFFECTS[e.effect]));
    if (note) {
      const n = make('p', 'hh-now');
      n.append(make('strong', null, 'Right now: '), document.createTextNode(note));
      rows.push(n);
    }
    tip.replaceChildren(...rows);
  }
  // Beside the control, never over it: below when it fits, else above,
  // else whichever side has more room (the pop-up then scrolls).
  function place(el) {
    const vw = document.documentElement.clientWidth || window.innerWidth;
    const vh = window.innerHeight;
    const r = el.getBoundingClientRect();
    tip.style.maxWidth = Math.max(120, Math.min(340, vw - 2 * EDGE)) + 'px';
    tip.style.maxHeight = '';
    tip.style.left = '0px';
    tip.style.top = '0px';
    const w = tip.offsetWidth, h = tip.offsetHeight;
    const below = vh - r.bottom - GAP - EDGE, above = r.top - GAP - EDGE;
    let top;
    if (h <= below) top = r.bottom + GAP;
    else if (h <= above) top = r.top - GAP - h;
    else if (below >= above) { top = r.bottom + GAP; tip.style.maxHeight = Math.max(40, below) + 'px'; }
    else { const room = Math.max(40, above); tip.style.maxHeight = room + 'px'; top = r.top - GAP - Math.min(h, room); }
    let left = r.left;
    left = Math.min(left, vw - EDGE - w);
    left = Math.max(EDGE, left);
    tip.style.left = Math.round(left) + 'px';
    tip.style.top = Math.round(top) + 'px';
  }
  // Inside an open modal dialog everything outside it is inert, so the
  // pop-up moves into that dialog (it stays hoverable there).
  function adopt(node, el) {
    const owner = (el && el.closest('dialog[open]')) || document.body;
    if (node.parentNode !== owner) {
      try { if (node.matches(':popover-open')) node.hidePopover(); } catch (err) { /* ignore */ }
      owner.appendChild(node);
    }
  }
  function topLayer(on) {
    if (!tip || !('popover' in tip)) return;
    try {
      if (on) { if (tip.matches(':popover-open')) tip.hidePopover(); tip.showPopover(); }
      else if (tip.matches(':popover-open')) tip.hidePopover();
    } catch (err) { /* not supported or not connected: the fixed position still works */ }
  }
  function show(el) {
    const item = wire(el) || entryFor(el);
    if (!item || dismissed === el) return false;
    build();
    clock.clear(leaveTimer);
    current = el;
    adopt(tip, el);
    fill(el, item);
    tip.hidden = false;
    topLayer(true);
    place(el);
    tip.setAttribute('data-for', el.getAttribute('data-hh') || '');
    return true;
  }
  function hide() {
    clock.clear(hoverTimer); clock.clear(leaveTimer);
    if (tip) { topLayer(false); tip.hidden = true; }
    hideInfo();
    current = null;
    hovering.tip = false;
  }
  function leaveSoon() {
    clock.clear(leaveTimer);
    leaveTimer = clock.set(() => {
      if (hovering.control || hovering.tip) return;
      if (current && current === document.activeElement && current.matches(':focus-visible')) return;
      hide();
    }, LEAVE_GRACE);
  }

  // ── The ⓘ target for touch ──────────────────────────────────────────
  function showInfo(el) {
    if (!info || !info.isConnected) {
      info = make('button', 'hh-info', 'ⓘ');
      info.type = 'button';
      info.tabIndex = -1;
      info.setAttribute('data-hh-ui', '');
      info.setAttribute('aria-label', 'What this control does');
      if ('popover' in info) info.setAttribute('popover', 'manual');
      info.addEventListener('click', ev => {
        ev.preventDefault(); ev.stopPropagation();
        const target = info.__for;
        if (!target) return;
        if (current === target && tip && !tip.hidden) hide();
        else { dismissed = null; show(target); showInfo(target); }
      });
      document.body.appendChild(info);
    }
    info.__for = el;
    adopt(info, el);
    info.hidden = false;
    try { if ('popover' in info) { if (info.matches(':popover-open')) info.hidePopover(); info.showPopover(); } } catch (err) { /* fixed position still works */ }
    const r = el.getBoundingClientRect();
    const vw = document.documentElement.clientWidth || window.innerWidth;
    const size = info.offsetWidth || 28;
    let left = r.right + 4;
    if (left + size > vw - 2) left = Math.max(2, r.left - 4 - size);
    info.style.left = Math.round(left) + 'px';
    info.style.top = Math.round(Math.max(2, r.top + (r.height - size) / 2)) + 'px';
  }
  function hideInfo() {
    if (!info) return;
    try { if (info.matches(':popover-open')) info.hidePopover(); } catch (err) { /* ignore */ }
    info.hidden = true;
  }

  // ── Events ──────────────────────────────────────────────────────────
  function onOver(ev) {
    if (ev.pointerType === 'touch') return;
    const el = controlFrom(ev.target);
    if (!el) return;
    hovering.control = true;
    clock.clear(leaveTimer);
    if (current === el) return;
    clock.clear(hoverTimer);
    hoverTimer = clock.set(() => { if (hovering.control) show(el); }, HOVER_DELAY);
  }
  function onOut(ev) {
    const el = controlFrom(ev.target);
    if (!el || (ev.relatedTarget && el.contains(ev.relatedTarget))) return;
    hovering.control = false;
    clock.clear(hoverTimer);
    if (dismissed === el) dismissed = null;
    leaveSoon();
  }
  function onFocus(ev) {
    const el = controlFrom(ev.target);
    if (!el || el !== ev.target) return;
    let visible = true;
    try { visible = el.matches(':focus-visible'); } catch (err) { visible = true; }
    if (visible) show(el);
  }
  function onBlur(ev) {
    const el = controlFrom(ev.target);
    if (!el) return;
    if (dismissed === el) dismissed = null;
    if (current === el && !(ev.relatedTarget && tip && tip.contains(ev.relatedTarget))) {
      if (hovering.control || hovering.tip) return;
      hide();
    }
  }
  function onKey(ev) {
    if (ev.key !== 'Escape' && ev.key !== 'Esc') return;
    if (!tip || tip.hidden) return;
    dismissed = current;
    hide();   // focus stays where it is; other Esc handlers still run
  }
  function onDown(ev) {
    clock.clear(pressTimer);
    if (ev.pointerType !== 'touch') return;
    const el = controlFrom(ev.target);
    if (!el) return;
    showInfo(el);
    pressTimer = clock.set(() => { dismissed = null; show(el); }, LONG_PRESS);
  }
  function onUp() { clock.clear(pressTimer); }
  function reposition() { if (current && tip && !tip.hidden) { if (current.isConnected) place(current); else hide(); } }

  function start() {
    if (!document.body) { document.addEventListener('DOMContentLoaded', start, { once: true }); return; }
    document.addEventListener('mouseover', onOver, true);
    document.addEventListener('mouseout', onOut, true);
    document.addEventListener('focusin', onFocus, true);
    document.addEventListener('focusout', onBlur, true);
    document.addEventListener('keydown', onKey, true);
    document.addEventListener('pointerdown', onDown, true);
    document.addEventListener('pointerup', onUp, true);
    document.addEventListener('pointercancel', onUp, true);
    window.addEventListener('scroll', reposition, true);
    window.addEventListener('resize', reposition);
    new MutationObserver(soon).observe(document.body, {
      subtree: true, childList: true, attributes: true, attributeFilter: ['title', 'id', 'class', 'role', 'type', 'hidden'],
    });
    scan();
  }

  // ── The coverage audit the tests (and anyone curious) can call ──────
  function audit(opts) {
    const all = !!(opts && opts.all);
    scan();
    return controls(document).filter(el => all || isVisible(el)).map(el => {
      const item = entryFor(el);
      const e = item ? item.e : {};
      return {
        page: pageKey(), control: describe(el), key: item ? item.sel : null,
        what: norm(e.what), input: norm(e.input), effect: e.effect || '',
        describedby: (el.getAttribute('aria-describedby') || '').split(/\s+/).filter(id => /^hh-/.test(id)),
        title: el.getAttribute('title') || '',
      };
    });
  }

  window.HoverHelp = {
    CONTROL, EFFECTS, clock, pageKey, entryFor, isControl, isVisible, controls, describe, audit, show, hide, scan,
    reset() { compiled = null; scan(); },
    tip: () => tip, info: () => info, current: () => current,
  };
  start();
})();
