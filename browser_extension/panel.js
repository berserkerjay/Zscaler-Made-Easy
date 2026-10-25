// The side panel: what DLP-Check knows about the DLP objects on the console
// page you are looking at (badges link here), a search over the tenant's
// dictionaries, engines and rules, and a stage of objects to export as a
// JSON pack or Terraform. Every answer comes from the DLP-Check app on this
// computer; the panel never calls Zscaler and never holds a credential.
import { api, apiBlob, appUrl, objectKey, ping } from './common.js';

const $ = id => document.getElementById(id);
const KIND = { dictionary: 'Dictionary', engine: 'Engine', rule: 'Rule' };
const S = { base: '', profiles: [], profile: '', index: null, byKey: new Map(), view: 'page', focus: null, stage: [], pageKeys: [], job: null, exportOpts: { format: 'json', deps: true } };

// ── DOM helpers (no HTML strings: every value is set as text) ──────
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  Object.entries(attrs || {}).forEach(([k, v]) => {
    if (v === undefined || v === null || v === false) return;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  });
  kids.flat().forEach(k => { if (k !== null && k !== undefined && k !== false) el.append(k instanceof Node ? k : document.createTextNode(String(k))); });
  return el;
}
const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + 's')}`;
const ago = t => { if (!t) return ''; const m = Math.round((Date.now() / 1000 - t) / 60); return m < 1 ? 'just now' : m < 60 ? `${m} min ago` : `${Math.round(m / 60)} h ago`; };
const worst = o => { const r = { high: 3, medium: 2, low: 1, info: 0 }; return (o.findings || []).reduce((a, f) => (r[f.severity] > r[a] ? f.severity : a), 'info'); };

// ── Storage (session: cleared when the browser closes) ──────────────
async function saveSession() {
  try { await chrome.storage.session.set({ index: S.index, profile: S.profile, stage: S.stage }); } catch (e) { /* nothing to keep */ }
}
async function loadSession() {
  try {
    const got = await chrome.storage.session.get(['index', 'profile', 'stage', 'focus']);
    S.index = got.index || null; S.stage = Array.isArray(got.stage) ? got.stage : []; S.focus = got.focus || null;
    if (got.profile !== undefined) S.profile = got.profile;
  } catch (e) { /* first open */ }
  indexMap();
}
function indexMap() {
  S.byKey = new Map(((S.index && S.index.objects) || []).map(o => [objectKey(o), o]));
}
const find = (kind, name) => [...S.byKey.values()].find(o => o.kind === kind && o.name === name);

// ── Connection, tenant and the read ──────────────────────────────────
async function connect() {
  S.base = await appUrl();
  const up = await ping(S.base);
  $('conn').textContent = up.ok ? 'Connected' : 'Not running';
  $('conn').className = 'chip ' + (up.ok ? 'ok' : 'bad');
  $('read').disabled = !up.ok;
  if (!up.ok) { $('readNote').textContent = `Start DLP-Check (${S.base.replace(/^https?:\/\//, '')}), or set its address in Settings.`; return false; }
  try {
    const d = await api(S.base, '/api/tenant-profiles');
    S.profiles = (d && d.profiles) || [];
  } catch (e) { S.profiles = []; $('readNote').textContent = e.message; }
  const sel = $('tenant');
  sel.replaceChildren(...S.profiles.map(p => h('option', { value: p.id, text: p.name || p.vanity_domain || p.id })),
    h('option', { value: '', text: 'Saved on this computer (environment or tenant_config.json)' }));
  if (!S.profile && S.profiles.length) S.profile = S.profiles[0].id;
  sel.value = S.profile || '';
  return true;
}
async function readTenant(refresh) {
  $('read').disabled = true; $('readNote').textContent = 'Reading the tenant through DLP-Check (read-only)…';
  try {
    const idx = await api(S.base, '/api/console-index', { profile_id: S.profile || '', refresh: !!refresh });
    S.index = idx; indexMap(); await saveSession();
    chrome.runtime.sendMessage({ type: 'index-updated' }).catch(() => {});
    noteRead();
  } catch (e) {
    $('readNote').textContent = e.message;
  } finally { $('read').disabled = false; }
  await refreshPage(); render();
}
function noteRead() {
  const x = S.index;
  if (!x) { $('readNote').textContent = 'Not read yet: read the tenant to see badges and details.'; $('read').textContent = 'Read the tenant'; return; }
  const c = x.counts || {};
  $('read').textContent = 'Read again';
  $('readNote').textContent = `${x.tenant_label || 'Tenant'}: ${plural(c.rule || 0, 'rule')}, ${plural(c.engine || 0, 'engine')}, ${plural(c.dictionary || 0, 'dictionary', 'dictionaries')}; read ${ago(x.cached_at || x.read_at)}.`;
}

// ── What the console page shows (the content script answers) ────────
async function refreshPage() {
  S.pageKeys = null;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id !== undefined) {
      const res = await chrome.tabs.sendMessage(tab.id, { type: 'list' });
      S.pageKeys = (res && Array.isArray(res.keys)) ? res.keys : [];
    }
  } catch (e) { S.pageKeys = null; }   // no badge script on this tab
}

// ── Views ────────────────────────────────────────────────────────────
function objRow(o) {
  const sev = worst(o);
  const meta = o.kind === 'dictionary' ? `Used by ${plural(o.counts.engines || 0, 'engine')} in ${plural(o.counts.rules || 0, 'rule')}`
    : o.kind === 'engine' ? `${plural(o.counts.dictionaries || 0, 'dictionary', 'dictionaries')} · used by ${plural(o.counts.rules || 0, 'rule')}`
      : `${o.channel_label || o.channel} · ${String(o.state || '').toLowerCase() || 'state ?'} · ${plural(o.counts.engines || 0, 'engine')}`;
  return h('li', {}, h('button', { type: 'button', class: 'obj', onclick: () => showDetail(objectKey(o)) },
    h('span', { class: 'nm', text: o.name }),
    h('span', {}, h('span', { class: 'chip kind', text: KIND[o.kind] }), ' ', (o.findings || []).length ? h('span', { class: `chip sev-${sev}`, text: plural(o.findings.length, 'finding') }) : null),
    h('span', { class: 'meta', text: meta + (o.pack ? ` · pack ${o.pack}` : '') })));
}
function list(objs, empty) {
  return objs.length ? h('ul', { class: 'list' }, objs.map(objRow)) : h('p', { class: 'empty', text: empty });
}
function viewPage() {
  if (!S.index) return h('p', { class: 'empty', text: 'Read the tenant to see what DLP-Check knows about the objects on this page.' });
  if (S.pageKeys === null) return h('p', { class: 'empty', text: 'No badges on this tab. Open the ZIA admin console (DLP dictionaries, engines or rules), and switch the badges on in Settings if you have not.' });
  const objs = S.pageKeys.map(k => S.byKey.get(k)).filter(Boolean);
  return list(objs, 'None of the DLP objects DLP-Check read are on this page.');
}
function viewSearch() {
  if (!S.index) return h('p', { class: 'empty', text: 'Read the tenant first.' });
  const box = h('input', { type: 'search', placeholder: 'Find a dictionary, engine or rule', 'aria-label': 'Find a dictionary, engine or rule' });
  const out = h('div');
  const run = () => {
    const q = box.value.trim().toLowerCase();
    const objs = [...S.byKey.values()].filter(o => !q || o.name.toLowerCase().includes(q)).slice(0, 200);
    out.replaceChildren(list(objs, 'Nothing matches.'));
  };
  box.addEventListener('input', run); run();
  setTimeout(() => box.focus(), 0);
  return h('div', {}, box, h('div', { style: 'height:8px' }), out);
}
function viewStage() {
  const objs = S.stage.map(k => S.byKey.get(k)).filter(Boolean);
  const wrap = h('div');
  if (!objs.length) return h('p', { class: 'empty', text: 'Nothing staged. Open an object and choose Stage for export: build a selection across console pages, then export it as a JSON pack or Terraform.' });
  const fmt = S.exportOpts.format;
  const radio = (v, label) => h('label', {}, h('input', { type: 'radio', name: 'fmt', value: v, checked: fmt === v, onchange: () => { S.exportOpts.format = v; } }), label);
  wrap.append(
    h('ul', { class: 'list' }, objs.map(o => h('li', {}, h('div', { class: 'obj' },
      h('span', { class: 'nm', text: o.name }),
      h('button', { type: 'button', 'aria-label': `Remove ${o.name} from the stage`, onclick: () => unstage(objectKey(o)), text: 'Remove' }),
      h('span', { class: 'meta', text: KIND[o.kind] + (o.channel_label ? ` · ${o.channel_label}` : '') }))))),
    h('div', { class: 'opts', role: 'group', 'aria-label': 'Export options' },
      radio('json', ' JSON pack'), radio('terraform', ' Terraform'), radio('both', ' JSON pack and Terraform'),
      h('label', {}, h('input', { type: 'checkbox', checked: S.exportOpts.deps, onchange: e => { S.exportOpts.deps = e.target.checked; } }), ' Include what they use')),
    h('div', { class: 'row' },
      h('button', { type: 'button', class: 'primary', id: 'exportGo', onclick: runExport, text: `Export ${plural(objs.length, 'object')}` }),
      h('button', { type: 'button', onclick: () => { S.stage = []; saveSession(); render(); }, text: 'Clear' })),
    h('p', { class: 'note', id: 'exportNote', text: 'Read-only: DLP-Check reads the tenant and writes nothing. Deploying or removing stays in DLP-Check, with write mode and its preview.' }));
  return wrap;
}
function refButtons(kind, names) {
  if (!names || !names.length) return h('span', { class: 'note', text: 'none' });
  return h('div', { class: 'refs' }, names.map(n => {
    const o = find(kind, n);
    return o ? h('button', { type: 'button', onclick: () => showDetail(objectKey(o)), text: n }) : h('span', { class: 'chip', text: n });
  }));
}
function viewDetail(o) {
  const staged = S.stage.includes(objectKey(o));
  const kv = [];
  const add = (k, v) => { if (v !== undefined && v !== null && v !== '') kv.push(h('dt', { text: k }), h('dd', {}, v)); };
  add('Kind', KIND[o.kind] + (o.kind === 'dictionary' && o.custom === false ? ' (predefined)' : ''));
  if (o.kind === 'rule') { add('Channel', o.channel_label || o.channel); add('State', String(o.state || '').toLowerCase()); add('Action', String(o.action || '').toLowerCase()); }
  if (o.kind === 'dictionary' && o.type) add('Type', String(o.type).toLowerCase().replace(/_/g, ' '));
  add('Created by', o.pack ? `policy pack ${o.pack}` : 'not by a DLP-Check pack');
  const uses = o.uses || {}, by = o.used_by || {};
  const sections = [];
  if (o.kind === 'engine') sections.push(h('h3', { text: 'Uses dictionaries' }), refButtons('dictionary', uses.dictionaries));
  if (o.kind === 'rule') sections.push(h('h3', { text: 'Uses engines' }), refButtons('engine', uses.engines));
  if (o.kind === 'dictionary') sections.push(h('h3', { text: `Used by engines (${o.counts.engines || 0})` }), refButtons('engine', by.engines),
    h('h3', { text: `Reaches rules (${o.counts.rules || 0})` }), refButtons('rule', by.rules));
  if (o.kind === 'engine') sections.push(h('h3', { text: `Used by rules (${o.counts.rules || 0})` }), refButtons('rule', by.rules));
  const findings = (o.findings || []).map(f => h('div', { class: `finding sev-${f.severity}` }, h('span', { class: `chip sev-${f.severity}`, text: f.severity }), ' ', f.text));
  const sub = o.kind === 'rule' && o.parent_id != null;
  return h('div', { class: 'detail' },
    h('button', { type: 'button', onclick: () => { S.focus = null; render(); }, text: '← Back' }),
    h('p', { class: 'title', text: o.name }),
    h('dl', { class: 'kv' }, kv),
    ...sections,
    h('h3', { text: 'Findings' }), findings.length ? findings : h('p', { class: 'note', text: 'None.' }),
    h('div', { class: 'row' },
      sub ? h('span', { class: 'note', text: 'An endpoint sub-rule is exported with its parent rule.' })
        : h('button', { type: 'button', class: staged ? '' : 'primary', onclick: () => (staged ? unstage(objectKey(o)) : stage(objectKey(o))), text: staged ? 'Remove from the stage' : 'Stage for export' }),
      h('button', { type: 'button', onclick: () => chrome.tabs.create({ url: S.base + '/' }), text: 'Open DLP-Check' })));
}
function render() {
  document.querySelectorAll('.seg [role="tab"]').forEach(t => t.setAttribute('aria-selected', String(t.dataset.v === S.view && !S.focus)));
  $('stageCount').textContent = String(S.stage.length);
  const o = S.focus ? S.byKey.get(S.focus) : null;
  const v = o ? viewDetail(o) : S.view === 'search' ? viewSearch() : S.view === 'stage' ? viewStage() : viewPage();
  $('view').replaceChildren(v);
}
function showDetail(key) { S.focus = key; render(); }
function stage(key) { if (!S.stage.includes(key)) S.stage.push(key); saveSession(); render(); }
function unstage(key) { S.stage = S.stage.filter(k => k !== key); saveSession(); render(); }

// ── Export the stage (read-only job in DLP-Check) ────────────────────
async function runExport() {
  const objs = S.stage.map(k => S.byKey.get(k)).filter(Boolean);
  const dictionaries = objs.filter(o => o.kind === 'dictionary' && o.id != null).map(o => String(o.id));
  const engines = objs.filter(o => o.kind === 'engine' && o.id != null).map(o => String(o.id));
  const rules = {};
  objs.filter(o => o.kind === 'rule' && o.id != null && o.parent_id == null).forEach(o => { (rules[o.channel] = rules[o.channel] || []).push(String(o.id)); });
  const parts = [dictionaries.length && 'dictionaries', engines.length && 'engines', Object.keys(rules).length && 'rules'].filter(Boolean);
  const note = $('exportNote'), go = $('exportGo');
  go.disabled = true; note.textContent = 'Exporting through DLP-Check…';
  try {
    const start = await api(S.base, '/api/dlp-packs/export/start', {
      profile_id: S.profile || '', parts, dictionaries, engines, rules: Object.keys(rules).length ? rules : {},
      include_dependencies: S.exportOpts.deps, format: S.exportOpts.format, pack_name: 'Console selection' });
    let since = 0, snap = null;
    for (;;) {
      snap = await api(S.base, `/api/dlp-packs/jobs/${encodeURIComponent(start.job_id)}?since=${since}`);
      since = snap.next || since;
      const last = (snap.logs || []).slice(-1)[0];
      if (last) note.textContent = last;
      if (snap.status !== 'running') break;
      await new Promise(r => setTimeout(r, 800));
    }
    const res = snap.result || {};
    if (res.status !== 'ready' || !snap.download) throw new Error(res.error || res.stopped || snap.error || 'The export did not finish.');
    const file = await apiBlob(S.base, snap.download);
    const a = h('a', { href: URL.createObjectURL(file.blob), download: file.name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    note.textContent = `Downloaded ${file.name}.`;
  } catch (e) {
    note.textContent = '';
    note.after(h('p', { class: 'err', role: 'alert', text: `Export failed: ${e.message}` }));
  } finally { go.disabled = false; }
}

// ── Wiring ───────────────────────────────────────────────────────────
document.querySelectorAll('.seg [role="tab"]').forEach((t, i, all) => {
  t.addEventListener('click', async () => { S.view = t.dataset.v; S.focus = null; if (S.view === 'page') await refreshPage(); render(); });
  t.addEventListener('keydown', e => {
    const d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (!d) return; e.preventDefault(); const n = all[(i + d + all.length) % all.length]; n.focus(); n.click();
  });
});
$('tenant').addEventListener('change', async e => { S.profile = e.target.value; S.index = null; indexMap(); await saveSession(); noteRead(); render(); });
$('read').addEventListener('click', () => readTenant(!!S.index));
$('settings').addEventListener('click', e => { e.preventDefault(); chrome.runtime.openOptionsPage(); });
$('openApp').addEventListener('click', e => { e.preventDefault(); chrome.tabs.create({ url: S.base + '/' }); });
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'session' && changes.focus && changes.focus.newValue) { S.focus = changes.focus.newValue.key || null; render(); }
});
chrome.tabs.onActivated.addListener(async () => { if (S.view === 'page' && !S.focus) { await refreshPage(); render(); } });

(async () => {
  await loadSession();
  if (S.focus && S.focus.key) S.focus = S.focus.key;
  const up = await connect();
  noteRead();
  if (up) await refreshPage();
  render();
})();
