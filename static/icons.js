// One symbol set for the whole app (Human Interface Guidelines: symbols,
// not emoji). Every icon is an inline SVG on a 24-point grid, drawn with
// currentColor, so it takes the text colour and size of wherever it sits
// and renders the same on every platform. Bundled here so the app keeps
// working offline; no icon font, no CDN.
//
//   window.dlpIcon(name, size)     → the SVG markup for one symbol
//   window.dlpIconize(root)        → replaces emoji used as icons under root
//
// The pages and add-ons kept their emoji characters in the markup (the
// tests pin them, and they are a readable fallback); this file swaps each
// one for its symbol at load and whenever new content is rendered: an
// emoji that is the whole content of an aria-hidden span, a .db-ico, a
// channel icon, or the first character of a button, heading, summary,
// label or list item. Text inside code, pre, inputs and options is left
// alone.
(function () {
  if (window.dlpIcon) return;
  // Paths on a 24×24 grid, stroke-drawn.
  const P = {
    'chart-bar': 'M3 3v18h18M7 16V9M12 16V5M17 16v-6',
    'lock': 'M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4',
    'lock-open': 'M5 11h14v10H5zM8 11V7a4 4 0 0 1 7.8-1.3',
    'lock-badge': 'M5 11h10v10H5zM8 11V7a4 4 0 0 1 8 0M17 14l1 2h2l-1.6 1.2.6 2-1.9-1.4L15.2 19l.6-2L14 16h2z',
    'target': 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM12 6a6 6 0 1 0 0 12 6 6 0 0 0 0-12zM12 10a2 2 0 1 0 0 4 2 2 0 0 0 0-4z',
    'play': 'M7 4l13 8-13 8z',
    'stop': 'M6 6h12v12H6z',
    'clipboard': 'M9 4h6v3H9zM8 5H6a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V6a1 1 0 0 0-1-1h-2M9 12h6M9 16h6',
    'globe': 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM2 12h20M12 2c3 3 3 17 0 20M12 2c-3 3-3 17 0 20',
    'laptop': 'M4 5h16v11H4zM2 19h20',
    'desktop': 'M3 4h18v12H3zM9 20h6M12 16v4',
    'envelope': 'M3 5h18v14H3zM3 6l9 7 9-7',
    'cloud': 'M7 18a4 4 0 0 1-.6-7.95A6 6 0 0 1 18 9a4.5 4.5 0 0 1 0 9z',
    'cpu': 'M7 7h10v10H7zM10 10h4v4h-4zM12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2',
    'search': 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4',
    'download': 'M12 3v12M7 10l5 5 5-5M4 17v3h16v-3',
    'shield': 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
    'plug': 'M9 3v5M15 3v5M6 8h12v4a6 6 0 0 1-12 0zM12 18v3',
    'shuffle': 'M3 7h4l10 10h4M17 5l4 2-4 2M3 17h4l3-3M14 7l3 0M17 15l4 2-4 2',
    'puzzle': 'M10 3h4v3a2 2 0 0 0 4 0V3h3v4h-3a2 2 0 0 0 0 4h3v4h-3v3h-4v-3a2 2 0 0 0-4 0v3H6v-4h3a2 2 0 0 0 0-4H6V7h4z',
    'bricks': 'M3 5h18M3 12h18M3 19h18M3 5v14M21 5v14M9 5v7M15 5v7M12 12v7',
    'siren': 'M6 20h12M7 20v-6a5 5 0 0 1 10 0v6M12 3v2M5 6l1.5 1.5M19 6l-1.5 1.5M9 20v-6a3 3 0 0 1 6 0v6',
    'key': 'M8 8a5 5 0 1 0 4.6 7L21 15v-3l-2 0-1-2h-2l-1.4-1.4A5 5 0 0 0 8 8zM8 13a1 1 0 1 0 0-2 1 1 0 0 0 0 2z',
    'scroll': 'M6 3h12v14a4 4 0 0 1-4 4H6a3 3 0 0 1-3-3v-1h11M9 7h6M9 11h6',
    'receipt': 'M5 3h14v18l-2-1.5-2 1.5-2-1.5-2 1.5-2-1.5L7 21l-2-1.5zM8 8h8M8 12h8M8 16h5',
    'folder': 'M3 6h6l2 2h10v11H3z',
    'folders': 'M3 8h5l2 2h9v9H3zM6 5h5l2 2h8v2',
    'folder-open': 'M3 6h6l2 2h10v3H6l-3 8zM3 19h16l3-8',
    'warning': 'M12 3l10 18H2zM12 10v5M12 18v.5',
    'trend-down': 'M3 7l7 7 4-4 7 7M15 17h6v-6',
    'trend-up': 'M3 17l7-7 4 4 7-7M15 7h6v6',
    'check-circle': 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM8 12l3 3 5-6',
    'check-seal': 'M12 2l2.4 1.6 2.9-.3 1.1 2.7 2.5 1.5-.8 2.8.8 2.8-2.5 1.5-1.1 2.7-2.9-.3L12 22l-2.4-1.6-2.9.3-1.1-2.7-2.5-1.5.8-2.8L3.1 11l2.5-1.5 1.1-2.7 2.9.3zM8.5 12l2.5 2.5 4.5-5',
    'map': 'M3 6l6-2 6 2 6-2v14l-6 2-6-2-6 2zM9 4v14M15 6v14',
    'doc': 'M6 3h8l4 4v14H6zM14 3v4h4M9 12h6M9 16h6',
    'box': 'M3 8l9-4 9 4v9l-9 4-9-4zM3 8l9 4 9-4M12 12v9',
    'compass': 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM16 8l-2.5 6.5L7 17l2.5-6.5z',
    'repeat': 'M17 2l4 4-4 4M21 6H8a4 4 0 0 0-4 4v1M7 22l-4-4 4-4M3 18h13a4 4 0 0 0 4-4v-1',
    'rocket': 'M12 2c3 2 5 6 5 10l-2 3h-6l-2-3c0-4 2-8 5-10zM9 15l-3 5 4-1M15 15l3 5-4-1M12 9v.5',
    'question-circle': 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 1-1 1.7M12 17v.5',
    'antenna': 'M12 12v9M12 12a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM7.5 14.5a6 6 0 0 1 0-9M16.5 5.5a6 6 0 0 1 0 9M4.5 17.5a10 10 0 0 1 0-15M19.5 2.5a10 10 0 0 1 0 15',
    'stethoscope': 'M6 3v6a5 5 0 0 0 10 0V3M11 14v3a4 4 0 0 0 8 0v-2M19 12a2 2 0 1 0 0 4 2 2 0 0 0 0-4z',
    'book': 'M4 4h7a3 3 0 0 1 3 3v13a2 2 0 0 0-2-2H4zM20 4h-7a3 3 0 0 0-3 3v13a2 2 0 0 1 2-2h8z',
    'books': 'M4 4h4v16H4zM10 4h4v16h-4zM16 6l4-1 3 15-4 1z',
    'gear': 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1',
    'refresh': 'M20 11a8 8 0 0 0-14-4.5L4 8M4 4v4h4M4 13a8 8 0 0 0 14 4.5l2-1.5M20 20v-4h-4',
    'sparkles': 'M12 3l2 5 5 2-5 2-2 5-2-5-5-2 5-2zM19 15l1 2 2 1-2 1-1 2-1-2-2-1 2-1zM5 15l.8 1.7L7.5 17.5l-1.7.8L5 20l-.8-1.7L2.5 17.5l1.7-.8z',
    'hammer': 'M14 4l6 6-2 2-6-6zM12 6L4 14l-1 4 4-1 8-8',
    'flask': 'M9 3h6M10 3v6l-6 10a1 1 0 0 0 1 2h14a1 1 0 0 0 1-2l-6-10V3M7 16h10',
    'flag': 'M5 21V4M5 4h13l-3 4 3 4H5',
    'cross-case': 'M3 7h18v13H3zM9 7V4h6v3M12 11v5M9.5 13.5h5',
    'credit-card': 'M3 6h18v12H3zM3 10h18M7 15h4',
    'bank': 'M3 9l9-5 9 5H3zM5 9v8M9 9v8M15 9v8M19 9v8M3 20h18',
    'lightbulb': 'M9 18h6M10 21h4M12 3a6 6 0 0 0-3.5 10.9c.5.4.5 1.1.5 1.1v1h6v-1s0-.7.5-1.1A6 6 0 0 0 12 3z',
    'palette': 'M12 3a9 9 0 1 0 0 18c1.5 0 2-1 2-2s-1-1.5-1-2.5S14 15 15.5 15H17a4 4 0 0 0 4-4 9 9 0 0 0-9-8zM7.5 12a1 1 0 1 0 0-2 1 1 0 0 0 0 2zM10 8.5a1 1 0 1 0 0-2 1 1 0 0 0 0 2zM14.5 8a1 1 0 1 0 0-2 1 1 0 0 0 0 2z',
    'moon': 'M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z',
    'sun': 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
    'bolt': 'M13 2L4 14h7l-1 8 9-12h-7z',
    'hourglass': 'M6 3h12M6 21h12M8 3v3l4 5 4-5V3M8 21v-3l4-5 4 5v3',
    'trash': 'M4 7h16M9 7V4h6v3M6 7l1 14h10l1-14M10 11v6M14 11v6',
    'wrench': 'M14.7 6.3a4 4 0 0 0 5.4 5.4l-9.3 9.3a2 2 0 0 1-2.8-2.8l9.3-9.3a4 4 0 0 0-2.6-2.6z',
    'x': 'M6 6l12 12M18 6L6 18',
    'check': 'M5 12l5 5 9-11',
    'pencil': 'M4 20l4-1L19 8l-3-3L5 16zM14 7l3 3',
    'menu': 'M4 7h16M4 12h16M4 17h16',
    'chevron-down': 'M6 9l6 6 6-6',
    'chevron-up': 'M6 15l6-6 6 6',
    'expand': 'M4 10V4h6M20 14v6h-6M4 4l6 6M20 20l-6-6',
    'arrow-up-right': 'M7 17L17 7M8 7h9v9',
    'arrow-left': 'M19 12H5M11 6l-6 6 6 6',
    'print': 'M6 9V3h12v6M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2M6 14h12v7H6z',
    'party': 'M4 20l4-12 8 8zM14 4l1 2M19 5l-2 2M20 11l-2-.5M12 2l.5 2',
  };
  // Every emoji (and dingbat) the pages use as an icon, by symbol name.
  const EMOJI = {
    '📊': 'chart-bar', '🔐': 'lock', '🔒': 'lock', '🔓': 'lock-open', '🔏': 'lock-badge', '🎯': 'target', '▶': 'play', '■': 'stop',
    '📋': 'clipboard', '🌐': 'globe', '💻': 'laptop', '🖥': 'desktop', '✉': 'envelope', '☁': 'cloud', '🤖': 'cpu', '🔍': 'search', '🔎': 'search',
    '💾': 'download', '🛡': 'shield', '🔌': 'plug', '🔀': 'shuffle', '🧩': 'puzzle', '🧱': 'bricks', '🚨': 'siren', '🔑': 'key', '📜': 'scroll',
    '🧾': 'receipt', '📁': 'folder', '🗂': 'folders', '📂': 'folder-open', '⚠': 'warning', '📉': 'trend-down', '📈': 'trend-up', '✅': 'check-circle', '🎉': 'party',
    '🗺': 'map', '📄': 'doc', '📦': 'box', '🧭': 'compass', '🔁': 'repeat', '🔄': 'refresh', '🚀': 'rocket', '❓': 'question-circle', '📡': 'antenna',
    '🩺': 'stethoscope', '📖': 'book', '📚': 'books', '⚙': 'gear', '✨': 'sparkles', '🏗': 'hammer', '🧪': 'flask', '🇺🇸': 'flag', '🇪🇺': 'flag',
    '🏥': 'cross-case', '💳': 'credit-card', '🏦': 'bank', '💡': 'lightbulb', '🎨': 'palette', '🌙': 'moon', '☀': 'sun', '⚡': 'bolt', '⏳': 'hourglass',
    '🗑': 'trash', '🔧': 'wrench', '☰': 'menu', '⤢': 'expand', '✎': 'pencil', '🖨': 'print',
  };
  // Dingbats the pages use as glyphs get the same treatment.
  Object.assign(EMOJI, { '✕': 'x', '✗': 'x', '✓': 'check', '↻': 'refresh', '↺': 'refresh', '↗': 'arrow-up-right', '←': 'arrow-left', '▾': 'chevron-down', '▴': 'chevron-up', '▲': 'chevron-up', '▼': 'chevron-down' });
  const norm = s => String(s || '').replace(/[️‍]/g, '');
  const keys = Object.keys(EMOJI).sort((a, b) => b.length - a.length);
  const ANY = new RegExp('(' + keys.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')\\uFE0F?');
  function svg(name, size) {
    const d = P[name]; if (!d) return '';
    const s = size || '1em';
    return `<svg class="ico ico-${name}" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="${d}"/></svg>`;
  }
  const SKIP = 'code, pre, textarea, script, style, svg, option, .no-ico';
  // Every text node under root: each emoji it holds becomes a symbol in an
  // aria-hidden span (a text node that is nothing but the emoji, inside an
  // icon span, becomes the symbol alone).
  function iconize(root) {
    root = root || document.body; if (!root || root.nodeType !== 1) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, { acceptNode: n => (n.nodeValue && ANY.test(n.nodeValue) && n.parentElement && !n.parentElement.closest(SKIP)) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP });
    const nodes = []; let n; while ((n = walker.nextNode())) nodes.push(n);
    for (const node of nodes) {
      const parent = node.parentElement; if (!parent) continue;
      const parts = node.nodeValue.split(ANY);   // text, emoji, text, emoji, … (capture group keeps the emoji)
      const frag = document.createDocumentFragment();
      for (let i = 0; i < parts.length; i++) {
        const piece = parts[i]; if (!piece) continue;
        const name = (i % 2 === 1) ? EMOJI[norm(piece)] : null;
        if (name) { const w = document.createElement('span'); w.className = 'ico-w'; w.setAttribute('aria-hidden', 'true'); w.innerHTML = svg(name); frag.appendChild(w); }
        else frag.appendChild(document.createTextNode(piece));
      }
      parent.replaceChild(frag, node);
      parent.classList.add('has-ico');
    }
  }
  window.dlpIcon = (name, size) => svg(name, size);
  window.dlpIconize = iconize;
  window.dlpIconName = e => EMOJI[norm(e)] || null;
  if (!document.getElementById('dlpIconStyle')) {
    const st = document.createElement('style'); st.id = 'dlpIconStyle';
    st.textContent = '.ico{display:inline-block;vertical-align:-0.15em;flex:none}.ico-w{display:inline-flex;align-items:center;vertical-align:-0.1em}.ico-w .ico{width:1.05em;height:1.05em}.db-ico .ico,.db-ch-ico .ico{width:1.15em;height:1.15em}';
    (document.head || document.documentElement).appendChild(st);
  }
  let queued = false;
  const schedule = () => { if (queued) return; queued = true; requestAnimationFrame(() => { queued = false; try { iconize(document.body); } catch (e) { /* cosmetic */ } }); };
  const start = () => {
    iconize(document.body);
    if (window.MutationObserver) new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true, characterData: true });
  };
  if (document.body) start(); else document.addEventListener('DOMContentLoaded', start);
})();
