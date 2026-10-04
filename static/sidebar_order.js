// ── Sidebar order: drag, keyboard and a per-browser saved order ──────
// The dashboard sidebar (dashboard.js) is a list of sections (Workflow,
// Start, Find the gaps, …), each a heading followed by items (buttons).
// This add-on lets the operator rearrange it:
//   - drag an item to another place in its section or into another one;
//   - drag a section heading to move the whole section;
//   - Alt+↑ / Alt+↓ moves the focused item one place through the sidebar
//     (crossing into the next or previous section at its ends);
//     Alt+Shift+↑ / Alt+Shift+↓ moves the focused item's whole section.
// Every move is announced through the page's live region and the focus
// stays on the moved item. Dragging is pointer based (no library, no
// HTML5 drag images that buttons refuse in some browsers): a press that
// moves less than a few pixels is an ordinary click; only a real drag
// reorders, and the click that follows a drag is swallowed.
//
// The order is saved in this browser's localStorage under stable ids (an
// item's data-sb-id, its workflow key, or its onclick call; a section's
// data-sb-id), never labels or positions. On load the saved order is
// merged with what the page has now: ids the page no longer has are
// dropped, and items or sections the saved order does not know appear in
// their default place. Stored data is only ever used to look up existing
// nodes by id and move them; nothing from storage is inserted as HTML.
//
// Nothing is renumbered: the ① ② ③ workflow numbers live on the step
// strip above the content and mean workflow order, not sidebar position.
(function () {
  'use strict';
  const KEY = 'dlpcheck_sidebar_order_v1';
  const ID_RE = /^[A-Za-z0-9_:.~-]{1,160}$/;
  const MAX_RAW = 64 * 1024;
  const DRAG_THRESHOLD = 6;   // px a press must travel before it is a drag

  const validId = s => typeof s === 'string' && ID_RE.test(s);
  const slug = s => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);

  // Parse what localStorage holds. Anything malformed means "no saved
  // order" (null), so a corrupt value falls back to the default.
  function parse(raw) {
    if (typeof raw !== 'string' || !raw || raw.length > MAX_RAW) return null;
    let d;
    try { d = JSON.parse(raw); } catch (e) { return null; }
    if (!d || typeof d !== 'object' || d.v !== 1 || !Array.isArray(d.sections)) return null;
    const out = [];
    for (const s of d.sections.slice(0, 200)) {
      if (!s || typeof s !== 'object' || !validId(s.id)) continue;
      out.push({ id: s.id, items: Array.isArray(s.items) ? s.items.filter(validId).slice(0, 500) : [] });
    }
    return out;
  }

  // Merge a saved order onto the page's default one: unknown ids are
  // dropped, duplicates keep their first place, and whatever the saved
  // order lacks goes where the default puts it (after its default
  // predecessor when that is in the same place, else first).
  function merge(def, saved) {
    const clone = o => o.map(s => ({ id: s.id, items: s.items.slice() }));
    if (!Array.isArray(saved)) return clone(def);
    const knownSec = new Set(def.map(s => s.id));
    const knownItem = new Set();
    def.forEach(s => s.items.forEach(i => knownItem.add(i)));
    const out = [], seenSec = new Set(), seenItem = new Set();
    for (const s of saved) {
      if (!s || !knownSec.has(s.id) || seenSec.has(s.id)) continue;
      seenSec.add(s.id);
      const items = [];
      for (const i of s.items || []) { if (knownItem.has(i) && !seenItem.has(i)) { seenItem.add(i); items.push(i); } }
      out.push({ id: s.id, items });
    }
    def.forEach((s, idx) => {
      if (seenSec.has(s.id)) return;
      seenSec.add(s.id);
      let at = 0;
      for (let k = idx - 1; k >= 0; k--) { const p = out.findIndex(r => r.id === def[k].id); if (p >= 0) { at = p + 1; break; } }
      out.splice(at, 0, { id: s.id, items: [] });
    });
    def.forEach(s => {
      const sec = out.find(r => r.id === s.id);
      s.items.forEach((i, idx) => {
        if (seenItem.has(i)) return;
        seenItem.add(i);
        let at = 0;
        for (let k = idx - 1; k >= 0; k--) { const p = sec.items.indexOf(s.items[k]); if (p >= 0) { at = p + 1; break; } }
        sec.items.splice(at, 0, i);
      });
    });
    return out;
  }

  function init(opts) {
    const o = Object.assign({
      root: null,                          // the sidebar (keyboard, pointer and click listeners)
      container: null,                     // the element whose children are the sections
      sectionSel: '.db-nav, .tool-group',
      headerSel: '.db-nav-l, .tool-group-l',
      itemSel: '.db-item, .btn',
      narrowQuery: '(max-width: 1000px)',  // dragging is off at this width; Alt+arrows still work
      menuHost: null,                      // where the "Sidebar order" menu goes (the sidebar foot)
      storage: null,
    }, opts || {});
    const root = o.root, box = o.container;
    if (!root || !box) return null;
    const doc = root.ownerDocument, win = doc.defaultView;
    const store = o.storage || (() => { try { return win.localStorage; } catch (e) { return null; } })();
    const say = t => {
      try {
        if (typeof win.announce === 'function') { win.announce(t); return; }
        const lr = doc.getElementById('liveRegion');
        if (lr) { lr.textContent = ''; setTimeout(() => { lr.textContent = t; }, 50); }
      } catch (e) { /* announcing is best effort */ }
    };

    // ── The model: read straight from the DOM every time ──────────
    const isSection = el => el && el.nodeType === 1 && el.parentElement === box && el.matches(o.sectionSel);
    const isItem = el => el && el.nodeType === 1 && isSection(el.parentElement) && el.matches(o.itemSel);
    const isHeader = el => el && el.nodeType === 1 && isSection(el.parentElement) && el.matches(o.headerSel);
    const sections = () => [...box.children].filter(isSection);
    const itemsOf = sec => [...sec.children].filter(isItem);
    const headerOf = sec => [...sec.children].find(isHeader) || null;
    const shown = el => el.getClientRects().length > 0;   // skips sections or items another add-on hides
    const used = new Set();
    function idFor(el, kind) {
      if (validId(el.dataset.sbId)) return el.dataset.sbId;
      let id = '';
      if (kind === 'section') id = 'grp-' + slug(el.getAttribute('aria-label') || (headerOf(el) || {}).textContent);
      else if (el.dataset.db) id = 'wf-' + slug(el.dataset.db);
      else if (el.id) id = 'id-' + el.id.replace(/[^A-Za-z0-9_-]/g, '');
      else if (el.getAttribute('onclick')) id = 'fn-' + el.getAttribute('onclick').replace(/[^A-Za-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 120);
      if (!validId(id)) return '';
      let u = id, n = 2;
      while (used.has(u)) u = `${id}~${n++}`;
      used.add(u);
      el.dataset.sbId = u;
      return u;
    }
    function tag() {
      const all = [];
      sections().forEach(s => { all.push([s, 'section']); itemsOf(s).forEach(i => all.push([i, 'item'])); });
      all.forEach(([el]) => { if (validId(el.dataset.sbId)) used.add(el.dataset.sbId); });
      all.forEach(([el, kind]) => { if (!validId(el.dataset.sbId)) idFor(el, kind); });
    }
    function current() {
      tag();
      return sections().filter(s => validId(s.dataset.sbId)).map(s => ({ id: s.dataset.sbId, items: itemsOf(s).map(i => i.dataset.sbId).filter(validId) }));
    }
    // An item carries the non-item nodes right after it (dashboard.js puts
    // its "Sign in first" note just below Scope assessment).
    function followers(item) {
      const out = [];
      for (let n = item.nextElementSibling; n && !isItem(n) && !isHeader(n); n = n.nextElementSibling) out.push(n);
      return out;
    }
    function keepFocus(fn) {
      const a = doc.activeElement;
      fn();
      if (a && a !== doc.body && doc.activeElement !== a && root.contains(a)) { try { a.focus({ preventScroll: true }); } catch (e) { a.focus(); } }
    }
    function placeItem(item, sec, before) {
      const nodes = [item].concat(followers(item));
      nodes.forEach(n => { if (before) sec.insertBefore(n, before); else sec.appendChild(n); });
    }
    function placeSection(sec, before) { if (before) box.insertBefore(sec, before); else box.appendChild(sec); }

    function apply(order) {
      tag();
      const secById = new Map(sections().map(s => [s.dataset.sbId, s]));
      const itemById = new Map();
      sections().forEach(s => itemsOf(s).forEach(i => itemById.set(i.dataset.sbId, i)));
      keepFocus(() => {
        order.forEach(s => {
          const sec = secById.get(s.id);
          if (!sec) return;
          placeSection(sec, null);
          s.items.forEach(id => { const it = itemById.get(id); if (it) placeItem(it, sec, null); });
        });
      });
    }

    const defaultOrder = current();
    function load() {
      let raw = null;
      try { raw = store ? store.getItem(KEY) : null; } catch (e) { raw = null; }
      return parse(raw);
    }
    function save() {
      try { if (store) store.setItem(KEY, JSON.stringify({ v: 1, sections: current() })); } catch (e) { /* private mode or full: the order still holds for this page */ }
    }
    function reset() {
      try { if (store) store.removeItem(KEY); } catch (e) { /* ignore */ }
      apply(merge(defaultOrder, null));
      say('Sidebar order reset to the default.');
    }
    apply(merge(defaultOrder, load()));

    // ── Names for the announcements ───────────────────────────────
    function nameOf(el) {
      let t = '';
      el.childNodes.forEach(n => { if (n.nodeType === 3) t += n.textContent; else if (n.nodeType === 1 && n.getAttribute('aria-hidden') !== 'true') t += n.textContent; });
      t = t.replace(/\s+/g, ' ').trim();
      return t || (el.getAttribute('aria-label') || '').trim() || 'Item';
    }
    function sectionName(sec) {
      const h = headerOf(sec);
      return ((h && h.textContent) || sec.getAttribute('aria-label') || 'section').replace(/\s+/g, ' ').trim();
    }
    function sayItem(item) {
      const sec = item.parentElement;
      const its = itemsOf(sec).filter(shown);
      say(`Moved ${nameOf(item)} to position ${its.indexOf(item) + 1} of ${its.length} in ${sectionName(sec)}.`);
    }
    function saySection(sec) {
      const ss = sections().filter(shown);
      say(`Moved section ${sectionName(sec)} to position ${ss.indexOf(sec) + 1} of ${ss.length}.`);
    }

    // ── Keyboard moves ────────────────────────────────────────────
    function nextItemEl(it) { let n = it.nextElementSibling; while (n && !isItem(n)) n = n.nextElementSibling; return n; }
    function moveItem(item, delta) {
      if (!isItem(item)) return false;
      const sec = item.parentElement;
      const its = itemsOf(sec).filter(i => i === item || shown(i));
      const k = its.indexOf(item);
      const ss = sections().filter(s => s === sec || shown(s));
      const si = ss.indexOf(sec);
      let to, before;
      if (delta < 0) {
        if (k > 0) { to = sec; before = its[k - 1]; } else if (si > 0) { to = ss[si - 1]; before = null; }
      } else if (k < its.length - 1) { to = sec; before = nextItemEl(its[k + 1]); } else if (si < ss.length - 1) { to = ss[si + 1]; before = itemsOf(to)[0] || null; }
      if (!to) { say(`${nameOf(item)} is already at the ${delta < 0 ? 'top' : 'bottom'} of the sidebar.`); return false; }
      keepFocus(() => placeItem(item, to, before));
      save(); sayItem(item);
      return true;
    }
    function moveSection(sec, delta) {
      if (!isSection(sec)) return false;
      const ss = sections().filter(s => s === sec || shown(s));
      const k = ss.indexOf(sec);
      if ((delta < 0 && k === 0) || (delta > 0 && k === ss.length - 1)) { say(`Section ${sectionName(sec)} is already ${delta < 0 ? 'first' : 'last'}.`); return false; }
      keepFocus(() => { if (delta < 0) placeSection(sec, ss[k - 1]); else placeSection(sec, ss[k + 1].nextElementSibling); });
      save(); saySection(sec);
      return true;
    }
    function itemFrom(t) {
      for (let el = t; el && el !== root; el = el.parentElement) if (isItem(el)) return el;
      return null;
    }
    root.addEventListener('keydown', e => {
      if (!e.altKey || e.ctrlKey || e.metaKey || (e.key !== 'ArrowUp' && e.key !== 'ArrowDown')) return;
      const item = itemFrom(e.target);
      if (!item) return;
      e.preventDefault(); e.stopPropagation();
      const d = e.key === 'ArrowUp' ? -1 : 1;
      if (e.shiftKey) moveSection(item.parentElement, d); else moveItem(item, d);
      if (doc.activeElement !== item) item.focus();
    });

    // ── Pointer dragging ──────────────────────────────────────────
    const mq = win.matchMedia ? win.matchMedia(o.narrowQuery) : null;
    const dragOn = () => !(mq && mq.matches);
    const syncDrag = () => {
      root.classList.toggle('sb-drag-on', dragOn());
      sections().forEach(s => itemsOf(s).forEach(i => i.setAttribute('aria-keyshortcuts', 'Alt+ArrowUp Alt+ArrowDown Alt+Shift+ArrowUp Alt+Shift+ArrowDown')));
    };
    syncDrag();
    if (mq) { try { mq.addEventListener('change', syncDrag); } catch (e) { try { mq.addListener(syncDrag); } catch (e2) { /* old engine */ } } }

    const line = doc.createElement('div');
    line.className = 'sb-drop-line'; line.setAttribute('aria-hidden', 'true'); line.hidden = true;
    root.appendChild(line);
    let drag = null, swallowClick = false;

    function showLine(y, kind) {
      const r = box.getBoundingClientRect();
      line.hidden = false;
      line.classList.toggle('sb-drop-sec', kind === 'section');
      line.style.top = `${Math.round(y) - 1}px`;
      line.style.left = `${Math.round(r.left)}px`;
      line.style.width = `${Math.round(r.width)}px`;
    }
    function itemTarget(y, dragged) {
      const ss = sections().filter(shown);
      if (!ss.length) return null;
      let sec = ss.find(s => s.getBoundingClientRect().bottom > y) || ss[ss.length - 1];
      const its = itemsOf(sec).filter(i => i !== dragged && shown(i));
      for (const it of its) {
        const r = it.getBoundingClientRect();
        if (y < r.top + r.height / 2) return { sec, before: it, y: r.top };
      }
      const last = its[its.length - 1];
      const h = headerOf(sec);
      const y2 = last ? last.getBoundingClientRect().bottom : (h ? h.getBoundingClientRect().bottom : sec.getBoundingClientRect().top);
      // After the last shown item: before the next item element in the DOM (a hidden one), else at the end.
      let before = last ? nextItemEl(last) : itemsOf(sec)[0] || null;
      while (before === dragged) before = nextItemEl(before);
      return { sec, before, y: y2 };
    }
    function sectionTarget(y, dragged) {
      const ss = sections().filter(s => s !== dragged && shown(s));
      for (const s of ss) {
        const r = s.getBoundingClientRect();
        if (y < r.top + r.height / 2) return { before: s, y: r.top - 2 };
      }
      const last = ss[ss.length - 1];
      let before = last ? last.nextElementSibling : null;
      while (before && (before === dragged || !isSection(before))) before = before.nextElementSibling;
      return { before, y: last ? last.getBoundingClientRect().bottom + 2 : 0 };
    }
    function endDrag(commit) {
      if (!drag) return;
      const d = drag; drag = null;
      line.hidden = true;
      root.classList.remove('sb-dragging');
      d.el.classList.remove('sb-drag-src');
      doc.removeEventListener('pointermove', onMove, true);
      doc.removeEventListener('pointerup', onUp, true);
      doc.removeEventListener('pointercancel', onCancel, true);
      doc.removeEventListener('keydown', onKey, true);
      if (!d.started) return;
      swallowClick = true; setTimeout(() => { swallowClick = false; }, 0);
      if (!commit || !d.target) return;
      const focusEl = d.kind === 'section' ? (itemsOf(d.el)[0] || null) : d.el;
      if (d.kind === 'section') {
        if (d.target.before === d.el) return;
        placeSection(d.el, d.target.before);
        save(); saySection(d.el);
      } else {
        if (d.target.before === d.el) return;
        placeItem(d.el, d.target.sec, d.target.before);
        save(); sayItem(d.el);
      }
      if (focusEl) { try { focusEl.focus({ preventScroll: true }); } catch (e) { focusEl.focus(); } }
    }
    function onMove(e) {
      if (!drag) return;
      if (!drag.started) {
        if (Math.abs(e.clientX - drag.x) < DRAG_THRESHOLD && Math.abs(e.clientY - drag.y) < DRAG_THRESHOLD) return;
        drag.started = true;
        root.classList.add('sb-dragging');
        drag.el.classList.add('sb-drag-src');
      }
      e.preventDefault();
      // Near the sidebar's top or bottom edge, scroll it along.
      const rr = root.getBoundingClientRect();
      if (e.clientY < rr.top + 28) root.scrollTop -= 12; else if (e.clientY > rr.bottom - 28) root.scrollTop += 12;
      drag.target = drag.kind === 'section' ? sectionTarget(e.clientY, drag.el) : itemTarget(e.clientY, drag.el);
      if (drag.target) showLine(drag.target.y, drag.kind);
    }
    function onUp() { endDrag(true); }
    function onCancel() { endDrag(false); }
    function onKey(e) { if (e.key === 'Escape' && drag) { e.preventDefault(); e.stopPropagation(); const started = drag.started; endDrag(false); if (started) say('Move cancelled.'); } }
    root.addEventListener('pointerdown', e => {
      if (!dragOn() || e.button !== 0 || e.pointerType === 'touch' || drag) return;
      let el = null, kind = '';
      for (let n = e.target; n && n !== root; n = n.parentElement) {
        if (isItem(n)) { el = n; kind = 'item'; break; }
        if (isHeader(n)) { el = n.parentElement; kind = 'section'; break; }
      }
      if (!el) return;
      drag = { el, kind, x: e.clientX, y: e.clientY, started: false, target: null };
      doc.addEventListener('pointermove', onMove, true);
      doc.addEventListener('pointerup', onUp, true);
      doc.addEventListener('pointercancel', onCancel, true);
      doc.addEventListener('keydown', onKey, true);
    });
    // The click a drag ends with is not an activation.
    root.addEventListener('click', e => { if (swallowClick) { swallowClick = false; e.preventDefault(); e.stopImmediatePropagation(); } }, true);

    // ── "Sidebar order" menu with Reset ───────────────────────────
    if (o.menuHost) {
      const det = doc.createElement('details');
      det.className = 'sb-menu'; det.id = 'sbOrderMenu';
      const sum = doc.createElement('summary');
      sum.textContent = 'Sidebar order';
      sum.title = 'Rearrange the sidebar, or put it back as it was';
      const pop = doc.createElement('div');
      pop.className = 'sb-menu-pop';
      const hint = doc.createElement('p');
      hint.id = 'sbOrderHint';
      hint.textContent = 'Drag an item, or a section heading, to move it. With an item focused: Alt+↑/↓ moves it, Alt+Shift+↑/↓ moves its section. The order is kept in this browser.';
      const btn = doc.createElement('button');
      btn.type = 'button'; btn.id = 'sbOrderReset'; btn.className = 'sb-menu-btn';
      btn.textContent = 'Reset sidebar order';
      btn.addEventListener('click', () => { reset(); det.open = false; sum.focus(); });
      pop.appendChild(hint); pop.appendChild(btn);
      det.appendChild(sum); det.appendChild(pop);
      det.addEventListener('keydown', e => { if (e.key === 'Escape' && det.open) { e.stopPropagation(); det.open = false; sum.focus(); } });
      o.menuHost.insertBefore(det, o.menuHost.firstChild);
    }

    return { KEY, defaultOrder, current, apply, reset, save, load, moveItem, moveSection, merge, parse };
  }

  window.SidebarOrder = { KEY, init, merge, parse };
})();
