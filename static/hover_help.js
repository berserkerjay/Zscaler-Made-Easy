// ── Help marks: a superscript ? (help) and * (new) after an item ──────
// Help opens only from a small superscript mark after a page title, a
// sidebar item or a control whose meaning or expected input the label does
// not say by itself. Pointing at, or tabbing to, an ordinary control, title
// or menu item opens nothing. The words for a control live in
// help_catalog.js (window.HELP_CATALOG), keyed per page by CSS selector:
// what it does, what input it expects, and whether it reads or changes the
// tenant. A page title's words are the page's own "What it is" (explain.js).
//
// Two marks, always in this order, each its own button and its own pop-up:
//   *  New in this version: "New in the <date> update: <what it is>". The
//      words come from whats_new.js (data-wn-new on the item).
//   ?  Help: the catalogue entry.
// Keeping them apart means the "new" line can go (Hide new marks, or the
// next release) without touching the help, and each mark's name says what
// it opens.
//
// How a mark works (WCAG 2.2): a real button, named "Help: <item>" or
// "New in this version: <item>", with aria-expanded and aria-controls the
// pop-up (role="tooltip"); its aria-describedby carries the same words, so
// a screen reader hears them on focus. Pointing at the mark opens the
// pop-up and it stays while the pointer is on the mark or the pop-up
// (1.4.13 hoverable); a click, a tap, or Enter or Space on the focused mark
// opens it and keeps it open; Esc, a click elsewhere, or opening another
// mark closes it (one at a time); focus never moves into it. The mark is
// 24 by 24 px (2.5.8) with negative margins, so it does not push the line
// apart; the ? or * is drawn by CSS, so the page's own words are unchanged.
// The pop-up is placed beside the mark, never over it, inside the viewport
// down to 320px. Every word is set with textContent, never as HTML.
//
// Which items get no "?" (skipReason): the label says it all (Close,
// Cancel, OK, Back, Help, Skip to …, Download as CSV …), a tab (it names
// its panel), a step in a diagram (no button fits inside a picture), the page's own "What is this page" box (it is the
// explanation), one row of a table (the column says what it is), a link
// inside a sentence, an option or tile that carries its own description, and
// the second and later controls of the same kind in one list (the first
// carries the mark).
// Section headings get none: the page's "What is this page" box explains
// them. A native title on a described control is taken off (it would open
// its own tooltip on hover) and kept as the pop-up's "Note" line when it
// says more than the entry.
(function () {
  'use strict';
  if (window.HoverHelp) return;

  // What counts as a control: everything a person can press, type into or pick.
  const CONTROL = [
    'button', 'a[href]', 'input:not([type="hidden"])', 'select', 'textarea', 'summary',
    '[role="button"]', '[role="tab"]', '[role="checkbox"]', '[role="switch"]', '[role="radio"]',
    '[role="menuitem"]', '[role="menuitemcheckbox"]', '[role="menuitemradio"]', '[role="option"][tabindex]',
    '[contenteditable="true"]',
  ].join(',');
  const EFFECTS = {
    local: 'Stays in this app. It does not touch your tenant.',
    read: 'Reads your tenant. It changes nothing there.',
    write: 'Can change your tenant. It needs write mode, a writer, the named assessor and your confirmation first.',
    confirm: 'Typing it lets the change go ahead. Cancel stops it.',
    download: 'Saves a file on this computer. It changes nothing in your tenant.',
    nav: 'Opens a page. It changes nothing by itself.',
  };
  // Labels that say it all: no "?" after them (compared without icons,
  // arrows or punctuation, case ignored).
  const OBVIOUS = new Set(['close', 'cancel', 'ok', 'okay', 'done', 'back', 'yes', 'no', 'next', 'previous', 'stop', 'reload',
    'refresh', 'find', 'search', 'copy', 'clear', 'reset', 'print', 'more', 'less', 'show more', 'show less', 'play', 'pause',
    'step', 'csv', 'json', 'pdf', 'xlsx', 'excel', 'word', 'markdown', 'download', 'dismiss', 'got it', 'not now', 'later',
    'no thanks', 'skip', 'light mode', 'dark mode', 'x', 'help', 'play motion', 'pause motion', 'replay']);
  const OBVIOUS_RE = /^(back to .+|skip to .+|download( as)? (csv|json|pdf|excel|word|markdown|xlsx)|(csv|json|pdf|excel|word|markdown) download)$/;
  const HOVER_DELAY = 250;   // ms of pointing at a mark before it opens (moving across a row stays quiet)
  const LEAVE_GRACE = 200;   // ms to move the pointer from the mark onto the pop-up
  const GAP = 6;             // px between the mark and the pop-up
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
  // Remembered per element until its attributes or its parent change (a
  // page rescans on every change, and matching every key is the costly part).
  let memo = new WeakMap();
  const sigOf = el => Array.from(el.attributes).filter(a => !/^(data-hh|aria-describedby$|aria-expanded$)/.test(a.name)).map(a => a.name + '=' + a.value).join('|');
  function remembered(el) {
    const m = memo.get(el), sig = sigOf(el);
    if (m && m.sig === sig && m.parent === el.parentElement && m.page === pageKey() && m.cat === catalogue()) return m;
    const fresh = { sig, parent: el.parentElement, page: pageKey(), cat: catalogue(), item: undefined, skip: undefined, words: undefined };
    memo.set(el, fresh);
    return fresh;
  }
  function entryFor(el) {
    const m = remembered(el);
    if (m.item !== undefined) return m.item;
    m.item = null;
    for (const item of catalogue().list) {
      let hit = false;
      try { hit = el.matches(item.sel); } catch (err) { hit = false; }
      if (hit) { m.item = item; break; }
    }
    return m.item;
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

  // ── Names ───────────────────────────────────────────────────────────
  // The words that name an item on screen: its labels or its own text,
  // without what is hidden from screen readers, other fields or our marks.
  function textOf(node) {
    let t = '';
    node.childNodes.forEach(n => {
      if (n.nodeType === 3) t += n.nodeValue;
      else if (n.nodeType === 1 && n.getAttribute('aria-hidden') !== 'true' && !n.matches('input, select, textarea, [data-hh-ui]')) t += ' ' + textOf(n);
    });
    return t;
  }
  function nameOf(el) {
    const labels = el.matches && el.matches('input, select, textarea') ? Array.from(el.labels || []) : [];
    let n = norm(labels.length ? labels.map(textOf).join(' ') : textOf(el));
    if (!n) n = norm(el.getAttribute('aria-label') || el.getAttribute('placeholder') || el.getAttribute('data-hh-title') || el.getAttribute('title') || el.value || '');
    return n.length > 80 ? n.slice(0, 79) + '…' : n;
  }
  const plain = s => norm(s).toLowerCase().replace(/[^\p{L}\p{N}' ]+/gu, ' ').replace(/\s+/g, ' ').trim();

  // ── Which controls get a "?" ────────────────────────────────────────
  // Why an item gets no "?", or '' when it gets one. Kept short and in one
  // place; the coverage test lists every skipped control with this reason.
  function skipReason(el, item) {
    item = item === undefined ? entryFor(el) : item;
    if (!item) return 'no entry';
    const m = remembered(el), words = plain(nameOf(el));
    if (m.skip !== undefined && m.words === words) return m.skip;
    m.words = words;
    m.skip = whySkip(el, item, words);
    return m.skip;
  }
  function whySkip(el, item, words) {
    if (!words || OBVIOUS.has(words) || OBVIOUS_RE.test(words) || words.length < 2) return 'the label says it all';
    if (el.closest('svg')) return 'a step in a diagram: the picture and its words name it';
    if (el.matches('[role="tab"]')) return 'a tab names its panel';
    if (el.closest('#xpBox')) return 'part of the page\'s own "What is this page" box';
    if (el.closest('tbody tr, [role="row"]') && !el.closest('thead')) return 'one row of a table: its column says what it is';
    if (el.matches('a[href]') && getComputedStyle(el).display === 'inline' && el.parentElement
        && norm(el.parentElement.textContent).length > norm(el.textContent).length + 20) return 'a link inside a sentence';
    if (el.matches('input[type="radio"], input[type="checkbox"], [role="radio"], [role="checkbox"]')
        && (el.hasAttribute('aria-describedby') || Array.from(el.labels || []).some(l => l.querySelector('.df-hint, .hint, small'))))
      return 'an option with its own description';
    if (el.matches('button, a[href], [role="button"], summary') && (norm(textOf(el)).length > 60 || el.querySelector('.df-hint, .hint, small, p')))
      return 'a tile that carries its own description';
    const box = el.parentElement && el.parentElement.closest('ul, ol, table, fieldset, [role="list"], [role="listbox"], [role="group"], [role="radiogroup"], .rp-bar') || el.parentElement;
    if (box) {
      for (const other of box.querySelectorAll(CONTROL)) {
        if (other === el) break;
        if (!ours(other) && entryFor(other) === item) return 'the first of the same kind in this list carries the mark';
      }
    }
    return '';
  }

  // ── Descriptions for screen readers ─────────────────────────────────
  // One hidden description per catalogue entry (per open dialog, so a
  // modal's inert background never hides it), shared by every mark of that
  // entry; a mark with its own words (a Note line, a title, what is new)
  // gets its own.
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
  function lines(content) {
    if (content.news) return [content.news];
    const e = content.e;
    const parts = [norm(e.what)];
    if (e.input) parts.push('Input: ' + norm(e.input));
    if (EFFECTS[e.effect]) parts.push(EFFECTS[e.effect]);
    if (content.note) parts.push('Note: ' + content.note);
    return parts;
  }
  function describeMark(mark, content) {
    const host = descHost(mark);
    const shared = content.item && !content.note;
    const id = shared ? `hh-d-${content.item.idx}-${host.dataset.hhScope}` : (mark.__hhDesc || 'hh-n-' + (++serial));
    let span = document.getElementById(id);
    if (!span) { span = document.createElement('span'); span.id = id; host.appendChild(span); }
    span.textContent = lines(content).join(' ');
    if (!shared) mark.__hhDesc = id;
    mark.setAttribute('aria-describedby', id);
  }

  // ── Native titles ───────────────────────────────────────────────────
  // The element whose native title describes the control: the control, or
  // the <label> around it (a label's title would open a second tooltip too).
  function titleHost(el) {
    if (el.hasAttribute('title') || el.hasAttribute('data-hh-title')) return el;
    const lab = el.closest('label');
    if (lab && (lab.hasAttribute('title') || lab.hasAttribute('data-hh-title'))) return lab;
    return Array.from(el.labels || []).find(l => l.hasAttribute('title') || l.hasAttribute('data-hh-title')) || el;
  }
  function noteOf(el, item) {
    const t = norm(titleHost(el).getAttribute('data-hh-title'));
    if (!t) return '';
    const known = norm(item.e.what + ' ' + item.e.input).toLowerCase();
    return known.includes(t.toLowerCase()) ? '' : t;
  }
  function untitle(el) {
    const host = titleHost(el);
    if (host.hasAttribute('title')) {
      host.setAttribute('data-hh-title', host.getAttribute('title'));
      host.removeAttribute('title');
    }
  }

  // ── The page title's words ──────────────────────────────────────────
  function titleEl() {
    return document.querySelector('.rp-hero h1, .hero h1, header h1, main h1') || null;
  }
  function pageWords() {
    const X = window.DLP_EXPLAIN, key = typeof window.DLP_EXPLAIN_KEY === 'function' ? window.DLP_EXPLAIN_KEY() : '';
    const x = X && key && X[key];
    return x && x.what ? { what: x.what, input: '', effect: '' } : null;
  }

  // ── Placing the marks ───────────────────────────────────────────────
  // After a control (a field wrapped in its label: after the label; a
  // checkbox or radio with its own label: after that label); inside a
  // title, heading, legend or <summary> (at the end of its words).
  function anchorOf(el) {
    if (!isControl(el) || el.matches('summary')) return { node: el, inside: true };
    const wrap = el.closest('label');
    if (wrap && wrap !== el) return { node: wrap, inside: false };
    if (el.matches('input[type="radio"], input[type="checkbox"]')) {
      const lab = Array.from(el.labels || [])[0];
      if (lab && !lab.contains(el)) return { node: lab, inside: true };
    }
    return { node: el, inside: false };
  }
  function makeMark(kind) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = kind === 'new' ? 'hh-mark hh-mark-new' : 'hh-mark';
    b.setAttribute('data-hh-ui', '');
    b.setAttribute('data-hh-mark', kind);
    b.setAttribute('aria-expanded', 'false');
    b.setAttribute('aria-controls', 'hhTip');
    return b;
  }
  // Put the marks right after the anchor (or at its end), * before ?.
  function seat(anchor, marks) {
    if (anchor.inside) {
      // Already the last children, in order: leave them (moving them would
      // be a change that asks for another scan).
      const tail = Array.from(anchor.node.children).slice(-marks.length);
      if (tail.length !== marks.length || tail.some((m, i) => m !== marks[i])) marks.forEach(m => anchor.node.appendChild(m));
    } else {
      let prev = anchor.node;
      marks.forEach(m => { if (prev.nextElementSibling !== m) prev.insertAdjacentElement('afterend', m); prev = m; });
    }
  }
  const items = new Map();   // item element → { help, news, anchor }
  let ro = null;
  function watchSize(el) {
    if (!ro && 'ResizeObserver' in window) ro = new ResizeObserver(entries => entries.forEach(en => sync(en.target)));
    if (ro) ro.observe(el);
  }
  // A mark shows only while its item is on the page.
  function sync(el) {
    const rec = items.get(el);
    if (!rec) return;
    const on = el.isConnected && el.getClientRects().length > 0 && !el.closest('[hidden]');
    [rec.help, rec.news].forEach(m => { if (m && m.hidden === on) m.hidden = !on; });
  }
  function drop(el) {
    const rec = items.get(el);
    if (!rec) return;
    [rec.help, rec.news].forEach(m => { if (m) { if (m === current) hide(); m.remove(); } });
    if (ro) ro.unobserve(el);
    items.delete(el);
  }
  function markItem(el, help, news) {
    let rec = items.get(el);
    if (!help && !news) { if (rec) drop(el); return; }
    if (!rec) { rec = { help: null, news: null }; items.set(el, rec); watchSize(el); }
    const name = nameOf(el) || 'this item';
    if (news) {
      if (!rec.news) { rec.news = makeMark('new'); rec.news.__hhFor = el; }
      rec.news.__hhContent = { news };
      rec.news.setAttribute('aria-label', 'New in this version: ' + name);
      describeMark(rec.news, rec.news.__hhContent);
    } else if (rec.news) { if (rec.news === current) hide(); rec.news.remove(); rec.news = null; }
    if (help) {
      if (!rec.help) { rec.help = makeMark('help'); rec.help.__hhFor = el; }
      rec.help.__hhContent = help;
      rec.help.setAttribute('aria-label', 'Help: ' + name);
      describeMark(rec.help, help);
    } else if (rec.help) { if (rec.help === current) hide(); rec.help.remove(); rec.help = null; }
    rec.anchor = anchorOf(el);
    seat(rec.anchor, [rec.news, rec.help].filter(Boolean));
    sync(el);
  }

  // ── Scanning the page ───────────────────────────────────────────────
  let pending = false;
  function scan() {
    pending = false;
    const want = new Map();
    controls(document).forEach(el => {
      const item = entryFor(el);
      if (item) untitle(el);
      const news = norm(el.getAttribute('data-wn-new'));
      const help = item && !skipReason(el, item) ? { item, e: item.e, note: noteOf(el, item) } : null;
      if (help || news) want.set(el, { help, news });
      if (item) el.setAttribute('data-hh', item.sel); else el.removeAttribute('data-hh');
    });
    // Titles and headings marked as new, and the page title's help.
    document.querySelectorAll('[data-wn-new]').forEach(el => {
      if (ours(el) || isControl(el) || want.has(el)) return;
      want.set(el, { help: null, news: norm(el.getAttribute('data-wn-new')) });
    });
    const h1 = titleEl(), words = h1 && pageWords();
    if (h1 && words) {
      const rec = want.get(h1) || { help: null, news: norm(h1.getAttribute('data-wn-new')) };
      rec.help = { e: words, title: true };
      want.set(h1, rec);
    }
    Array.from(items.keys()).forEach(el => { if (!want.has(el) || !el.isConnected) drop(el); });
    want.forEach((w, el) => markItem(el, w.help, w.news));
    // A mark left behind by an item that was re-rendered.
    document.querySelectorAll('.hh-mark').forEach(m => { if (!m.__hhFor || !items.has(m.__hhFor) || ![items.get(m.__hhFor).help, items.get(m.__hhFor).news].includes(m)) m.remove(); });
  }
  function soon() {
    if (pending) return;
    pending = true;
    (window.requestAnimationFrame || (f => clock.set(f, 16)))(scan);
  }

  // ── The pop-up ──────────────────────────────────────────────────────
  let tip = null, current = null, pinned = false;
  let hoverTimer = null, leaveTimer = null;
  const hovering = { mark: false, tip: false };
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
  function fill(content) {
    if (content.news) { tip.replaceChildren(make('p', 'hh-new', content.news)); return; }
    const e = content.e;
    const rows = [make('p', 'hh-what', norm(e.what))];
    if (e.input) {
      const inp = make('p', 'hh-input');
      inp.append(make('strong', null, 'Input: '), document.createTextNode(norm(e.input)));
      rows.push(inp);
    }
    if (EFFECTS[e.effect]) rows.push(make('p', 'hh-effect hh-' + e.effect, EFFECTS[e.effect]));
    if (content.note) {
      const n = make('p', 'hh-now');
      n.append(make('strong', null, 'Note: '), document.createTextNode(content.note));
      rows.push(n);
    }
    tip.replaceChildren(...rows);
  }
  // Beside the mark, never over it: below when it fits, else above, else
  // whichever side has more room (the pop-up then scrolls).
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
  function isMark(el) { return !!(el && el.nodeType === 1 && el.classList.contains('hh-mark')); }
  // Open a mark's pop-up. Given an item instead, its "?" (or its "*").
  function markOf(el) {
    if (isMark(el)) return el;
    const rec = items.get(el);
    return rec ? (rec.help || rec.news) : null;
  }
  function open(mark, keep) {
    if (!isMark(mark) || !mark.__hhContent || mark.hidden) return false;
    build();
    clock.clear(leaveTimer); clock.clear(hoverTimer);
    if (current && current !== mark) current.setAttribute('aria-expanded', 'false');
    current = mark;
    pinned = !!keep;
    adopt(tip, mark);
    fill(mark.__hhContent);
    tip.hidden = false;
    topLayer(true);
    place(mark);
    tip.setAttribute('data-for', mark.getAttribute('data-hh-mark') + ':' + ((mark.__hhFor && mark.__hhFor.getAttribute('data-hh')) || ''));
    mark.setAttribute('aria-expanded', 'true');
    return true;
  }
  // Open help for an item or a mark (the tests and other add-ons call it).
  function show(el) { return open(markOf(el), true); }
  function hide() {
    clock.clear(hoverTimer); clock.clear(leaveTimer);
    if (tip) { topLayer(false); tip.hidden = true; }
    if (current) current.setAttribute('aria-expanded', 'false');
    current = null;
    pinned = false;
    hovering.tip = false; hovering.mark = false;
  }
  function leaveSoon() {
    clock.clear(leaveTimer);
    leaveTimer = clock.set(() => {
      if (pinned || hovering.mark || hovering.tip) return;
      hide();
    }, LEAVE_GRACE);
  }

  // ── Events: only the marks open anything ────────────────────────────
  function markFrom(node) {
    const el = node && node.nodeType === 1 ? node : node && node.parentElement;
    return el && el.closest ? el.closest('.hh-mark') : null;
  }
  function onOver(ev) {
    if (ev.pointerType === 'touch') return;
    const m = markFrom(ev.target);
    if (!m) return;
    hovering.mark = true;
    clock.clear(leaveTimer);
    if (current === m) return;
    clock.clear(hoverTimer);
    hoverTimer = clock.set(() => { if (hovering.mark) open(m, false); }, HOVER_DELAY);
  }
  function onOut(ev) {
    const m = markFrom(ev.target);
    if (!m || (ev.relatedTarget && m.contains(ev.relatedTarget))) return;
    hovering.mark = false;
    clock.clear(hoverTimer);
    if (current === m) leaveSoon();
  }
  function onClick(ev) {
    const m = markFrom(ev.target);
    if (!m) return;
    // The mark is its own button: it never presses the item, the label or the summary around it.
    ev.preventDefault();
    ev.stopPropagation();
    if (current === m && pinned) hide(); else open(m, true);
  }
  function onDown(ev) {
    if (!tip || tip.hidden) return;
    const t = ev.target;
    if (tip.contains(t) || markFrom(t)) return;
    hide();   // a click or tap anywhere else closes it
  }
  function onKey(ev) {
    if (ev.key !== 'Escape' && ev.key !== 'Esc') return;
    if (!tip || tip.hidden) return;   // no pop-up: Esc goes on to the dialog or search behind it
    // The pop-up is open: this Esc is its own. A dialog's cancel, Find
    // anything's close or a sheet's Esc must not also run.
    ev.preventDefault();
    ev.stopImmediatePropagation();
    hide();   // focus stays where it is
  }
  function onBlur(ev) {
    const m = markFrom(ev.target);
    if (m && m === current && !pinned && !hovering.mark && !hovering.tip) hide();
  }
  function reposition() { if (current && tip && !tip.hidden) { if (current.isConnected && !current.hidden) place(current); else hide(); } }

  function start() {
    if (!document.body) { document.addEventListener('DOMContentLoaded', start, { once: true }); return; }
    build();
    document.addEventListener('mouseover', onOver, true);
    document.addEventListener('mouseout', onOut, true);
    document.addEventListener('click', onClick, true);
    document.addEventListener('pointerdown', onDown, true);
    document.addEventListener('keydown', onKey, true);
    document.addEventListener('focusout', onBlur, true);
    window.addEventListener('scroll', reposition, true);
    window.addEventListener('resize', reposition);
    // Changes inside our own marks and pop-up, or inside a picture (an
    // animated SVG redraws every frame), never ask for a rescan.
    const quiet = m => m.type === 'childList' && m.target.closest && !!m.target.closest('[data-hh-ui], svg');
    new MutationObserver(muts => { if (muts.some(m => !quiet(m))) soon(); }).observe(document.body, {
      subtree: true, childList: true, attributes: true, attributeFilter: ['title', 'id', 'class', 'role', 'type', 'hidden', 'data-wn-new'],
    });
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', scan, { once: true });
    scan();
  }

  // ── The coverage audit the tests (and anyone curious) can call ──────
  // One row per control: its entry, whether it has a "?", and if not why.
  function audit(opts) {
    const all = !!(opts && opts.all);
    scan();
    return controls(document).filter(el => all || isVisible(el)).map(el => {
      const item = entryFor(el);
      const e = item ? item.e : {};
      const rec = items.get(el) || {};
      return {
        page: pageKey(), control: describe(el), key: item ? item.sel : null,
        what: norm(e.what), input: norm(e.input), effect: e.effect || '',
        mark: !!rec.help, news: !!rec.news, skip: item ? skipReason(el, item) : '',
        name: rec.help ? rec.help.getAttribute('aria-label') : '',
        title: titleHost(el).getAttribute('data-hh-title') || '',
        nativeTitle: titleHost(el).getAttribute('title') || '',
      };
    });
  }
  function marks() { return Array.from(document.querySelectorAll('.hh-mark')); }

  window.HoverHelp = {
    CONTROL, EFFECTS, OBVIOUS, clock, pageKey, entryFor, titleHost, isControl, isVisible, controls, describe, audit, skipReason,
    nameOf, markOf, marks, open, show, hide, scan,
    reset() { compiled = null; memo = new WeakMap(); scan(); },
    tip: () => tip, current: () => current, pinned: () => pinned,
  };
  start();
})();
