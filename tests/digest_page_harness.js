// Runs the Digest page's inline script against a stubbed DOM and fetch.
// argv[2]: the page path; argv[3]: JSON {responses: {"<METHOD> <path>": {status, body}}, click: bool}.
// Prints {status, bad, warn, live, sched} after the page has loaded (and,
// with click, after Run the loop now has been clicked).
const fs = require('fs');
const vm = require('vm');
const html = fs.readFileSync(process.argv[2], 'utf8');
const cfg = JSON.parse(process.argv[3]);
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
const code = scripts[scripts.length - 1];

const els = {};
function el(id) {
  if (!els[id]) {
    const classes = new Set();
    els[id] = {
      id, textContent: '', innerHTML: '', className: '', disabled: false, href: '', listeners: {},
      classList: { toggle: (c, on) => { if (on) classes.add(c); else classes.delete(c); }, contains: c => classes.has(c) },
      setAttribute() {}, addEventListener(ev, fn) { this.listeners[ev] = fn; },
      querySelector() { return el(id + '__tbody'); },
    };
  }
  return els[id];
}
const pending = [];
const sandbox = {
  console,
  document: { getElementById: el },
  window: {},
  location: {},
  setTimeout: (fn) => { pending.push(fn); return 1; },
  setInterval: () => 1,
  clearInterval: () => {},
  fetch: async (url, opts) => {
    const key = `${(opts && opts.method) || 'GET'} ${String(url).split('?')[0]}`;
    const r = cfg.responses[key] || { status: 200, body: {} };
    return { ok: r.status >= 200 && r.status < 300, status: r.status,
             json: async () => r.body, text: async () => (typeof r.body === 'string' ? r.body : JSON.stringify(r.body)) };
  },
};
sandbox.window = sandbox;
vm.createContext(sandbox);
vm.runInContext(code, sandbox);

const tick = () => new Promise(r => setImmediate(r));
(async () => {
  for (let i = 0; i < 20; i++) await tick();
  if (cfg.click) {
    await el('dgRun').listeners.click();
    for (let i = 0; i < 20; i++) await tick();
  }
  pending.splice(0).forEach(fn => fn());
  const s = el('dgStatus');
  console.log(JSON.stringify({ status: s.textContent, bad: s.classList.contains('bad'), warn: s.classList.contains('warn'),
                               live: el('liveRegion').textContent, sched: el('dgSched').innerHTML, disabled: el('dgRun').disabled }));
})();
