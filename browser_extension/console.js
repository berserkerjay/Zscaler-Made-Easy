// In-console badges (runs only on the ZIA admin console, and only after the
// admin switched the badges on in the extension's settings).
//
// It looks for text on the page that is exactly the name of an object
// Zscaler Made Easy read from the tenant (DLP dictionaries, engines and rules; URL
// filtering, Cloud App Control, SSL inspection, Cloud Firewall and File
// Type Control rules; URL categories, locations, departments, groups, rule
// labels, network services, IP groups...) and puts a small badge after it:
// its most serious finding ("shadowed", "unused") or what uses it ("used in
// 4 rules"). Names that several objects share get one "N objects" badge.
// Clicking a badge opens the side panel on that object (or that list). The comparison happens here,
// in the page: no text of the console page is sent anywhere; the only thing
// that leaves is the key of an object Zscaler Made Easy already knows.
(() => {
  if (window.__dlpCheckBadges) return;
  window.__dlpCheckBadges = true;

  const MAX_BADGES = 400, MAX_NODES = 20000;
  const PALETTE = {
    light: { bg: 'rgba(0, 102, 204, 0.12)', fg: '#0066cc', high: '#d70015', medium: '#c93400', ring: '#0066cc' },
    dark: { bg: 'rgba(10, 132, 255, 0.16)', fg: '#0a84ff', high: '#ff453a', medium: '#ff9f0a', ring: '#0a84ff' },
  };
  let names = null;                 // name -> [{key, kind (its label), label, sev}]
  const badged = new Map();         // element -> keys
  let timer = 0;

  const dark = () => window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

  function badge(el, entries) {
    const host = document.createElement('span');
    host.setAttribute('data-dlpcheck-badge', '');
    host.style.cssText = 'display:inline-block;margin-left:6px;vertical-align:middle;';
    const root = host.attachShadow({ mode: 'closed' });
    const p = dark() ? PALETTE.dark : PALETTE.light;
    const e = entries[0];
    const order = { high: 3, medium: 2, low: 1, info: 0 };
    const sev = entries.reduce((a, x) => (order[x.sev] > order[a] ? x.sev : a), 'info');
    const sevColor = sev === 'high' ? p.high : sev === 'medium' ? p.medium : p.fg;
    const style = document.createElement('style');
    style.textContent = `button{all:unset;cursor:pointer;display:inline-flex;align-items:center;gap:4px;padding:0 7px;min-height:18px;border-radius:999px;`
      + `font:600 11px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;background:${p.bg};color:${sevColor};white-space:nowrap}`
      + `button:focus-visible{outline:2px solid ${p.ring};outline-offset:2px}`;
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = entries.length > 1 ? `Zscaler Made Easy · ${entries.length} objects` : `Zscaler Made Easy · ${e.label}`;
    b.title = entries.map(x => `${x.kind}: ${x.label}`).join('\n') + '\nOpen in the Zscaler Made Easy side panel';
    b.setAttribute('aria-label', `Zscaler Made Easy: ${entries.map(x => `${x.kind}, ${x.label}`).join('; ')}. Open in the side panel`);
    b.addEventListener('click', ev => {
      ev.preventDefault(); ev.stopPropagation();
      chrome.runtime.sendMessage({ type: 'focus', key: e.key, keys: entries.map(x => x.key) }).catch(() => {});
    });
    root.append(style, b);
    // Inside a table cell or list item, the badge stays in that cell; after an inline element otherwise.
    if (/^(TD|TH|LI|DD|DT)$/.test(el.tagName)) el.append(host); else el.after(host);
    badged.set(el, entries.map(x => x.key));
  }

  function scan() {
    timer = 0;
    if (!names || !document.body) return;
    for (const [el] of badged) if (!el.isConnected) badged.delete(el);
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode(n) {
        const p = n.parentElement;
        if (!p || p.closest('[data-dlpcheck-badge],script,style,textarea,input,select,[contenteditable="true"]')) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      },
    });
    let n, seen = 0;
    while ((n = walker.nextNode()) && seen++ < MAX_NODES && badged.size < MAX_BADGES) {
      const t = (n.nodeValue || '').trim();
      if (t.length < 2 || t.length > 255) continue;
      const hit = names[t];
      if (!hit) continue;
      const el = n.parentElement;
      // The whole element must be the name (not a sentence that mentions it).
      if (badged.has(el) || el.querySelector('[data-dlpcheck-badge]') || (el.textContent || '').trim() !== t
          || (el.nextElementSibling && el.nextElementSibling.hasAttribute('data-dlpcheck-badge'))) continue;
      badge(el, hit);
    }
  }
  const later = () => { if (!timer) timer = setTimeout(scan, 400); };

  function clear() {
    document.querySelectorAll('[data-dlpcheck-badge]').forEach(x => x.remove());
    badged.clear();
  }
  async function load() {
    try {
      const res = await chrome.runtime.sendMessage({ type: 'names' });
      names = res && res.names ? res.names : null;
    } catch (e) { names = null; }
    clear(); later();
  }

  chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
    if (!msg) return false;
    if (msg.type === 'list') { reply({ keys: [...new Set([...badged.values()].flat())] }); return false; }
    if (msg.type === 'refresh') { load(); return false; }
    return false;
  });
  new MutationObserver(later).observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  load();
})();
