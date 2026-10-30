/* Accessibility layer for the bundled reference documents (WCAG 2.2 AA).
 *
 * The reference pages (/reference/<slug>, and the two documents embedded
 * in them) are built elsewhere and bundled as they are, each with its own
 * palette and markup. The app serves them with this script (see
 * reference_page in dlp_api_server.py), which closes the gaps the Wave 6
 * UI check measured with axe-core, without editing their content:
 *   - 3.1.1  the page states its language;
 *   - 4.1.2  a dialog has a name; a card that is a button never holds
 *            another button (it gets its own "Open" button instead);
 *   - 2.1.1  a scrolling region with nothing focusable in it can be
 *            reached and scrolled with the keyboard;
 *   - 2.5.8  the small select buttons are 24 by 24 px;
 *   - 2.4.7  every control shows a strong focus ring;
 *   - 1.4.10 the tab bar and long code wrap at 320 px;
 *   - 1.4.3  text darker or lighter, in its own hue, where its colour is
 *            below 4.5:1 (3:1 when large) on what is painted under it.
 * It reads nothing from the network and changes no text.
 */
(function () {
  'use strict';
  if (window.__refA11y) return;
  window.__refA11y = true;
  const doc = document;

  // ── colour helpers (WCAG relative luminance) ──────────────────────
  // rgb()/rgba(), and color(srgb r g b / a), which color-mix() computes to.
  function rgba(s) {
    let m = /rgba?\(([^)]+)\)/.exec(s || '');
    if (m) { const v = m[1].split(/[\s,/]+/).filter(Boolean).map(Number); return { r: v[0], g: v[1], b: v[2], a: v.length > 3 ? v[3] : 1 }; }
    m = /color\(srgb\s+([^)]+)\)/.exec(s || '');
    if (m) { const v = m[1].split(/[\s/]+/).filter(Boolean).map(Number); return { r: v[0] * 255, g: v[1] * 255, b: v[2] * 255, a: v.length > 3 ? v[3] : 1 }; }
    return null;
  }
  const over = (f, b) => ({ r: f.r * f.a + b.r * (1 - f.a), g: f.g * f.a + b.g * (1 - f.a), b: f.b * f.a + b.b * (1 - f.a), a: 1 });
  function lum(c) {
    const f = x => { x /= 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
  }
  function ratio(a, b) { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); }
  function toHsl(c) {
    const r = c.r / 255, g = c.g / 255, b = c.b / 255, mx = Math.max(r, g, b), mn = Math.min(r, g, b);
    let h = 0, s = 0; const l = (mx + mn) / 2;
    if (mx !== mn) {
      const d = mx - mn; s = l > 0.5 ? d / (2 - mx - mn) : d / (mx + mn);
      h = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; h /= 6;
    }
    return { h, s, l };
  }
  function fromHsl(h, s, l) {
    if (!s) { const v = Math.round(l * 255); return { r: v, g: v, b: v, a: 1 }; }
    const q = l < 0.5 ? l * (1 + s) : l + s - l * s, p = 2 * l - q;
    const t = x => { x = x < 0 ? x + 1 : x > 1 ? x - 1 : x; return x < 1 / 6 ? p + (q - p) * 6 * x : x < 1 / 2 ? q : x < 2 / 3 ? p + (q - p) * (2 / 3 - x) * 6 : p; };
    return { r: Math.round(t(h + 1 / 3) * 255), g: Math.round(t(h) * 255), b: Math.round(t(h - 1 / 3) * 255), a: 1 };
  }
  // The colour in the same hue, moved in lightness away from `against` until it reaches `need`.
  function fix(color, against, need) {
    const hsl = toHsl(color), darker = lum(against) > 0.18;
    for (let i = 1; i <= 50; i++) {
      const l = Math.min(1, Math.max(0, hsl.l + (darker ? -0.02 : 0.02) * i));
      const c = fromHsl(hsl.h, hsl.s, l);
      if (ratio(c, against) >= need + 0.05) return c;
    }
    return darker ? { r: 0, g: 0, b: 0, a: 1 } : { r: 255, g: 255, b: 255, a: 1 };
  }
  const css = c => `rgb(${c.r}, ${c.g}, ${c.b})`;

  // What is painted under an element: its own and its ancestors' backgrounds, composited.
  function backdrop(el) {
    const layers = [];
    for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
      const s = getComputedStyle(n);
      if (s.backgroundImage && s.backgroundImage !== 'none') return null;   // a gradient or an image: not judged here
      const c = rgba(s.backgroundColor);
      if (c && c.a > 0) { layers.push({ c, el: n }); if (c.a >= 0.999) break; }
    }
    let bg = { r: 255, g: 255, b: 255, a: 1 };
    for (let i = layers.length - 1; i >= 0; i--) bg = over(layers[i].c, bg);
    return { bg, own: layers.length && layers[0].el === el && layers[0].c.a >= 0.999 ? layers[0].c : null };
  }
  function opacity(el) { let o = 1; for (let n = el; n && n.nodeType === 1; n = n.parentElement) o *= parseFloat(getComputedStyle(n).opacity || '1'); return o; }

  function repairContrast(root) {
    // Start from the document's own colours every time: a tab that became
    // active must show its own colour, not the one repaired for its last state.
    doc.querySelectorAll('[data-ref-a11y]').forEach(el => { el.style.removeProperty('color'); el.style.removeProperty('background-color'); el.removeAttribute('data-ref-a11y'); });
    const all = (root || doc.body).querySelectorAll('*');
    for (const el of all) {
      if (el.closest('svg, script, style, [aria-hidden="true"]')) continue;
      let text = false;
      for (const n of el.childNodes) if (n.nodeType === 3 && n.nodeValue.trim()) { text = true; break; }
      if (!text) continue;
      const r = el.getBoundingClientRect(); if (!r.width || !r.height) continue;
      if (opacity(el) < 0.5) continue;   // a dimmed, inactive card: not text a user is meant to read now
      const s = getComputedStyle(el), fg0 = rgba(s.color); if (!fg0 || !fg0.a) continue;
      const under = backdrop(el); if (!under) continue;
      const size = parseFloat(s.fontSize), bold = parseInt(s.fontWeight, 10) >= 700;
      const need = size >= 24 || (bold && size >= 18.66) ? 3 : 4.5;
      const fg = over(fg0, under.bg);
      if (ratio(fg, under.bg) >= need) continue;
      // White (or black) text on its own coloured badge: the badge darkens (or lightens), the text stays.
      const extreme = lum(fg) > 0.9 || lum(fg) < 0.01;
      if (extreme && under.own) el.style.setProperty('background-color', css(fix(under.own, fg, need)), 'important');
      else el.style.setProperty('color', css(fix(fg, under.bg, need)), 'important');
      el.setAttribute('data-ref-a11y', '1');
    }
  }

  // ── structure ────────────────────────────────────────────────────
  const FOCUSABLE = 'a[href], button, input, select, textarea, summary, [tabindex]:not([tabindex="-1"])';
  function nameDialogs() {
    doc.querySelectorAll('[role="dialog"], [role="alertdialog"], dialog').forEach(d => {
      if (d.getAttribute('aria-labelledby') || (d.getAttribute('aria-label') || '').trim()) return;
      const h = d.querySelector('h1, h2, h3, h4');
      d.setAttribute('aria-label', (h && h.textContent.trim().slice(0, 120)) || 'Details');
    });
  }
  // A card that is itself a button may not hold a button (4.1.2): the card
  // keeps its click; keyboard and screen-reader users get an "Open" button.
  function unnestButtons() {
    doc.querySelectorAll('[role="button"]').forEach(card => {
      if (!card.querySelector(FOCUSABLE)) return;
      const label = (card.getAttribute('aria-label') || card.textContent || 'Open').trim().slice(0, 160);
      card.removeAttribute('role'); card.removeAttribute('tabindex'); card.removeAttribute('aria-label');
      if (getComputedStyle(card).position === 'static') card.style.position = 'relative';
      const open = doc.createElement('button');
      open.type = 'button'; open.className = 'ref-a11y-open'; open.textContent = label;
      open.addEventListener('keydown', e => e.stopPropagation());   // the card's own Enter handler would open it a second time
      card.appendChild(open);
    });
  }
  // Something that only a mouse can click (a div with an onclick: the
  // channel toggles, the stat cards) becomes a button for the keyboard (2.1.1),
  // pressed or not when it toggles (.active), with Enter and Space.
  function clickables() {
    doc.querySelectorAll('body *').forEach(el => {
      if (!(el.hasAttribute('onclick') || typeof el.onclick === 'function') || el.matches(FOCUSABLE) || el.closest('svg')) return;
      if (el.closest(FOCUSABLE) || el.querySelector(FOCUSABLE)) return;
      if (!el.textContent.trim()) return;   // a backdrop that closes a dialog: its close button and Esc are the keyboard way
      el.setAttribute('role', 'button'); el.setAttribute('tabindex', '0');
      if (el.classList.contains('channel-toggle')) el.setAttribute('aria-pressed', String(el.classList.contains('active')));
      if (!el.__refKey) {
        el.__refKey = true;
        el.addEventListener('keydown', e => {
          if (e.key !== 'Enter' && e.key !== ' ') return;
          e.preventDefault();
          // A toggle redraws its row: keep the keyboard on the same item (2.4.3), not on the page.
          const sel = el.tagName.toLowerCase() + (el.classList[0] ? '.' + CSS.escape(el.classList[0]) : '');
          const idx = Array.prototype.indexOf.call(doc.querySelectorAll(sel), el);
          el.click();
          setTimeout(() => { if (el.isConnected) return; pass(); const n = doc.querySelectorAll(sel)[idx]; if (n && n.focus) n.focus(); }, 0);
        });
      }
    });
  }
  function scrollRegions() {
    doc.querySelectorAll('body *').forEach(el => {
      if (el.hasAttribute('tabindex') || el.matches(FOCUSABLE)) return;
      const s = getComputedStyle(el);
      const scrolls = (/(auto|scroll)/.test(s.overflowX) && el.scrollWidth > el.clientWidth + 1) || (/(auto|scroll)/.test(s.overflowY) && el.scrollHeight > el.clientHeight + 1);
      if (!scrolls || el.querySelector(FOCUSABLE)) return;
      el.setAttribute('tabindex', '0');
      if (!el.getAttribute('role') && /^(DIV|SECTION|PRE)$/.test(el.tagName)) el.setAttribute('role', 'region');   // a list keeps its list role
      if (!el.getAttribute('aria-label') && !el.getAttribute('aria-labelledby')) {
        const sec = el.closest('section, figure, article');
        const h = sec && sec.querySelector('h1, h2, h3, h4, figcaption');
        el.setAttribute('aria-label', ((h && h.textContent.trim()) || 'Scrollable content').slice(0, 120) + ' (scrolls)');
      }
    });
  }
  function focusColour() {
    const under = backdrop(doc.body) || { bg: { r: 255, g: 255, b: 255, a: 1 } };
    doc.documentElement.style.setProperty('--ref-a11y-focus', lum(under.bg) > 0.18 ? '#0047b3' : '#8ab8ff');
  }

  function style() {
    if (doc.getElementById('refA11yStyle')) return;
    const st = doc.createElement('style'); st.id = 'refA11yStyle';
    st.textContent = [
      'html.ref-a11y-measuring *, html.ref-a11y-measuring *::before, html.ref-a11y-measuring *::after { transition: none !important; }',
      'html body :focus-visible { outline: 3px solid var(--ref-a11y-focus, #0047b3) !important; outline-offset: 2px !important; }',
      '.tech-select { min-width: 24px !important; min-height: 24px !important; }',
      '.tab-bar { flex-wrap: wrap; } .tab-btn { white-space: normal; }',
      '@media (max-width: 480px) { .tab-bar { padding-left: 16px !important; padding-right: 16px !important; margin-left: 0 !important; margin-right: 0 !important; } .tab-btn { padding: 10px 12px !important; } }',
      'code, .why, .path { overflow-wrap: anywhere; }',
      '@media (max-width: 700px) { body :where(p, li, span, a, b, strong, em, code, dd, td, th, h1, h2, h3, h4, div) { overflow-wrap: anywhere; } }',
      '@media (max-width: 700px) { code { white-space: normal !important; } .trust li { flex-wrap: wrap; } .trust .arrow { min-width: 0 !important; white-space: normal !important; } }',
      '@media (max-width: 700px) { .framework-overview { grid-template-columns: minmax(0, 1fr) !important; } .framework-export-copy { min-width: 0 !important; } .overview-card { min-width: 0; overflow-wrap: anywhere; } }',
      '.ref-a11y-open { position: absolute; inset: 0; width: 100%; height: 100%; opacity: 0; border: 0; background: transparent; cursor: pointer; font-size: 0; z-index: 0; }',
      '.ref-a11y-open:focus-visible { opacity: 1; }',
      '[role="button"] ~ .tech-select, .technique > .tech-select { position: relative; z-index: 1; }',
    ].join('\n');
    (doc.head || doc.documentElement).appendChild(st);
  }

  let queued = false;
  function pass() {
    queued = false;
    try {
      if (!doc.documentElement.getAttribute('lang')) doc.documentElement.setAttribute('lang', 'en');
      style(); focusColour(); nameDialogs(); unnestButtons(); clickables(); scrollRegions();
      // Colours are measured at rest: transitions are held while the repair
      // runs (a colour caught mid-transition is neither the old nor the new one).
      doc.documentElement.classList.add('ref-a11y-measuring');
      try { repairContrast(); } finally { void doc.body.offsetWidth; doc.documentElement.classList.remove('ref-a11y-measuring'); }
    } catch (e) { console.warn('reference accessibility layer:', e && e.message); /* the document still works without it */ }
  }
  // Once soon after a change, and once more when transitions have settled.
  let later = 0;
  function schedule() { if (!queued) { queued = true; setTimeout(pass, 60); } clearTimeout(later); later = setTimeout(pass, 500); }
  window.__refA11yPass = pass;
  function start() {
    pass();
    if (window.MutationObserver) new MutationObserver(muts => { if (muts.some(m => !(m.target.id === 'refA11yStyle'))) schedule(); })
      .observe(doc.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['class', 'hidden', 'open', 'aria-selected', 'aria-pressed'] });
    window.addEventListener('resize', schedule);
  }
  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', start); else start();
})();
