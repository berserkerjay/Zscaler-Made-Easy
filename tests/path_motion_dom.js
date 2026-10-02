// A small stand-in for the browser, just enough to run static/path_motion.js
// under node for the tests (tests/test_path_analyzer.py): an HTML parser for
// the markup it writes, the few DOM calls it makes, SVG path lengths for
// M/H/V/L/C paths, and stubs for matchMedia, IntersectionObserver,
// visibility and requestAnimationFrame that the test drives by hand.
'use strict';
const vm = require('vm'), fs = require('fs');

const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", apos: "'" };
const decode = s => s.replace(/&(amp|lt|gt|quot|#39|apos);/g, (_, e) => ENT[e]);
const VOID = new Set(['img', 'br', 'input', 'meta', 'link', 'hr']);

class ClassList {
  constructor(el) { this.el = el; }
  _all() { return (this.el.attrs.class || '').split(/\s+/).filter(Boolean); }
  contains(c) { return this._all().includes(c); }
  add(c) { if (!this.contains(c)) this.el.attrs.class = this._all().concat(c).join(' '); }
  remove(c) { this.el.attrs.class = this._all().filter(x => x !== c).join(' '); }
  toggle(c, on) { if (on === undefined) on = !this.contains(c); if (on) this.add(c); else this.remove(c); return on; }
}

class El {
  constructor(tag, attrs) {
    this.tag = tag; this.attrs = Object.assign({}, attrs || {}); this.children = []; this.parent = null;
    this.classList = new ClassList(this); this.listeners = {}; this.text = '';
  }
  get dataset() {
    const d = {};
    Object.keys(this.attrs).filter(k => k.startsWith('data-')).forEach(k => { d[k.slice(5).replace(/-(\w)/g, (_, c) => c.toUpperCase())] = this.attrs[k]; });
    return d;
  }
  get id() { return this.attrs.id || ''; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k] == null ? null : this.attrs[k]; }
  removeAttribute(k) { delete this.attrs[k]; }
  appendChild(c) { if (c.parent) c.remove(); c.parent = this; this.children.push(c); return c; }
  remove() { if (this.parent) { this.parent.children = this.parent.children.filter(x => x !== this); this.parent = null; } }
  get textContent() { return this.tag === '#text' ? this.text : this.children.map(c => c.textContent).join(''); }
  set textContent(v) { this.children = []; if (v !== '') this.appendChild(Object.assign(new El('#text'), { text: String(v) })); }
  set innerHTML(h) { this.children = []; parse(String(h), this); }
  get innerHTML() { return this.children.map(c => c.outerHTML).join(''); }
  get outerHTML() {
    if (this.tag === '#text') return this.text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const a = Object.entries(this.attrs).map(([k, v]) => ` ${k}="${String(v).replace(/&/g, '&amp;').replace(/"/g, '&quot;')}"`).join('');
    return `<${this.tag}${a}>${this.innerHTML}</${this.tag}>`;
  }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  removeEventListener(t, f) { this.listeners[t] = (this.listeners[t] || []).filter(x => x !== f); }
  dispatch(t) { (this.listeners[t] || []).slice().forEach(f => f({ type: t })); }
  click() { this.dispatch('click'); }
  closest() { return null; }
  all() { const out = []; const walk = e => e.children.forEach(c => { if (c.tag !== '#text') { out.push(c); walk(c); } }); walk(this); return out; }
  matches(sel) {
    const m = sel.match(/^([a-z0-9]+)?((?:[.#][\w-]+)*)$/i);
    if (!m) throw new Error(`selector not supported by the stub: ${sel}`);
    if (m[1] && m[1].toLowerCase() !== this.tag) return false;
    return (m[2].match(/[.#][\w-]+/g) || []).every(p => (p[0] === '.' ? this.classList.contains(p.slice(1)) : this.id === p.slice(1)));
  }
  querySelectorAll(sel) {
    const parts = sel.trim().split(/\s+/);
    return this.all().filter(e => {
      if (!e.matches(parts[parts.length - 1])) return false;
      let i = parts.length - 2, p = e.parent;
      while (i >= 0 && p && p !== this) { if (p.matches(parts[i])) i--; p = p.parent; }
      return i < 0;
    });
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  // SVG geometry for the paths path_motion.js draws (a cubic counts as its chord).
  _segs() {
    const toks = (this.attrs.d || '').match(/[MLHVC][^MLHVC]*/g) || [];
    let x = 0, y = 0; const segs = [];
    toks.forEach(t => {
      const n = t.slice(1).trim().split(/[\s,]+/).filter(Boolean).map(Number);
      if (t[0] === 'M') { x = n[0]; y = n[1]; return; }
      let nx = x, ny = y;
      if (t[0] === 'H') nx = n[0]; else if (t[0] === 'V') ny = n[0]; else { nx = n[n.length - 2]; ny = n[n.length - 1]; }
      segs.push([x, y, nx, ny]); x = nx; y = ny;
    });
    return segs;
  }
  getTotalLength() { return this._segs().reduce((a, s) => a + Math.hypot(s[2] - s[0], s[3] - s[1]), 0); }
  getPointAtLength(len) {
    const segs = this._segs();
    for (const s of segs) {
      const l = Math.hypot(s[2] - s[0], s[3] - s[1]);
      if (len <= l) { const f = l ? len / l : 0; return { x: s[0] + (s[2] - s[0]) * f, y: s[1] + (s[3] - s[1]) * f }; }
      len -= l;
    }
    const s = segs[segs.length - 1] || [0, 0, 0, 0];
    return { x: s[2], y: s[3] };
  }
}

// Enough HTML to read what path_motion.js writes: tags, quoted or bare
// attributes, self-closing SVG tags, void tags and text with entities.
function parse(html, root) {
  let cur = root;
  const re = /<\/([\w:-]+)\s*>|<([\w:-]+)((?:\s+[\w:-]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'>/]+))?)*)\s*(\/?)>|([^<]+)|(<)/g;
  let m;
  while ((m = re.exec(html))) {
    if (m[1]) { let p = cur; while (p !== root && p.tag !== m[1].toLowerCase()) p = p.parent; if (p !== root) cur = p.parent; }
    else if (m[2]) {
      const attrs = {}, ar = /([\w:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>/]+)))?/g;
      let a; while ((a = ar.exec(m[3] || ''))) attrs[a[1]] = decode(a[2] != null ? a[2] : a[3] != null ? a[3] : a[4] != null ? a[4] : '');
      const el = cur.appendChild(new El(m[2].toLowerCase(), attrs));
      if (!m[4] && !VOID.has(el.tag)) cur = el;
    } else {
      const t = m[5] != null ? m[5] : m[6];
      cur.appendChild(Object.assign(new El('#text'), { text: decode(t) }));
    }
  }
}

// Loads path_motion.js into a fresh context with the stubs. opts.reduce sets
// what (prefers-reduced-motion: reduce) answers; opts.noFlatMap removes
// Array.prototype.flatMap first, as an ES2017 browser would lack it.
function load(file, opts) {
  opts = opts || {};
  const rafs = new Map(); let rafId = 0; const stats = { requested: 0, cancelled: 0 };
  const observers = [];
  const doc = new El('#document');
  doc.hidden = false;
  doc.createElementNS = (ns, tag) => new El(tag);
  doc.createElement = tag => new El(tag);
  const mq = new El('#mq'); mq.matches = !!opts.reduce;
  const ctx = {
    document: doc, console, setTimeout, clearTimeout,
    matchMedia: q => { if (q !== '(prefers-reduced-motion: reduce)') throw new Error(q); return mq; },
    requestAnimationFrame: f => { stats.requested++; rafs.set(++rafId, f); return rafId; },
    cancelAnimationFrame: id => { if (rafs.delete(id)) stats.cancelled++; },
    IntersectionObserver: class { constructor(cb) { this.cb = cb; this.targets = []; observers.push(this); } observe(t) { this.targets.push(t); } disconnect() { this.targets = []; } },
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  if (opts.noFlatMap) vm.runInContext('delete Array.prototype.flatMap;', ctx);
  vm.runInContext(fs.readFileSync(file, 'utf8'), ctx);
  let now = 0;
  return {
    ctx, doc, mq, stats, observers, El,
    run: code => vm.runInContext(code, ctx),
    pending: () => rafs.size,
    // Runs the frames that are waiting, `n` times, 1/60 s apart.
    frames(n) { for (let i = 0; i < (n || 1); i++) { const fs_ = [...rafs.values()]; rafs.clear(); now += 1000 / 60; fs_.forEach(f => f(now)); } },
    setHidden(h) { doc.hidden = h; doc.dispatch('visibilitychange'); },
    intersect(on) { observers.forEach(o => o.cb([{ isIntersecting: on }])); },
    container: () => new El('div'),
  };
}

module.exports = { load, El, parse };
