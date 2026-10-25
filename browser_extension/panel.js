// The side panel: what DLP-Check knows about the objects on the console
// page you are looking at (badges link here), a search over everything it
// read (DLP dictionaries, engines and rules; the ZIA policies' rules; URL
// categories, locations, groups and the other objects those rules use),
// filtered by kind, and a stage of DLP objects to export as a JSON pack or
// Terraform. Every answer comes from the DLP-Check app on this computer;
// the panel never calls Zscaler and never holds a credential.
import { PAGES, SHADOW_KINDS, api, apiBlob, appUrl, kindInfo, objectKey, ping } from './common.js';

const $ = id => document.getElementById(id);
const S = { base: '', profiles: [], profile: '', index: null, byKey: new Map(), view: 'page', focus: null, focusList: null, kind: '', query: '',
  stage: [], pageKeys: [], job: null, exportOpts: { format: 'json', deps: true } };
const kindLabel = kind => kindInfo(S.index, kind).label;
// Lower-case a label inside a sentence, but keep a leading acronym or product name (DLP, URL, Cloud Firewall).
const inSentence = t => (/^[A-Z][a-z]/.test(t) && !/^(Cloud|File Type|SSL|Inline|Endpoint|Outbound|SaaS)\b/.test(t) ? t[0].toLowerCase() + t.slice(1) : t);
const exportable = o => !!kindInfo(S.index, o.kind).export;
// A `uses` entry's key -> the kind it names (DLP keeps its plural keys).
const USES_KIND = { engines: 'engine', dictionaries: 'dictionary', rules: 'rule' };

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
  try { await chrome.storage.session.set({ index: S.index, profile: S.profile, stage: S.stage, kind: S.kind }); } catch (e) { /* nothing to keep */ }
}
async function loadSession() {
  try {
    const got = await chrome.storage.session.get(['index', 'profile', 'stage', 'focus', 'kind']);
    S.index = got.index || null; S.stage = Array.isArray(got.stage) ? got.stage : []; S.kind = typeof got.kind === 'string' ? got.kind : '';
    focusFrom(got.focus);
    if (got.profile !== undefined) S.profile = got.profile;
  } catch (e) { /* first open */ }
  indexMap();
}
// A badge click: one object, or the objects that share the clicked name.
function focusFrom(f) {
  if (!f) return;
  const keys = Array.isArray(f.keys) ? f.keys : (f.key ? [f.key] : []);
  if (keys.length > 1) { S.focusList = keys; S.focus = null; } else { S.focus = keys[0] || null; S.focusList = null; }
}
function indexMap() {
  S.byKey = new Map(((S.index && S.index.objects) || []).map(o => [objectKey(o), o]));
}
const find = (kind, name, policy) => [...S.byKey.values()].find(o => o.kind === kind && o.name === name && (!policy || kind !== 'rule' || !o.policy || o.policy === policy));

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
  const zia = ((x.kinds || []).filter(k => k.group !== 'DLP')).reduce((a, k) => a + (c[k.kind] || 0), 0);
  $('read').textContent = 'Read again';
  $('readNote').textContent = `${x.tenant_label || 'Tenant'}: ${plural(c.rule || 0, 'DLP rule')}, ${plural(c.engine || 0, 'engine')}, ${plural(c.dictionary || 0, 'dictionary', 'dictionaries')}`
    + (zia ? `, ${plural(zia, 'ZIA rule or object', 'ZIA rules and objects')}` : '') + `; read ${ago(x.cached_at || x.read_at)}.`;
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
const policyLabel = p => ((S.index && S.index.policy_labels) || {})[p] || p;
function usedIn(o) {
  const by = (o.counts && o.counts.by_policy) || {};
  const parts = Object.entries(by).map(([p, k]) => `${policyLabel(p)} ${k}`);
  return `used in ${plural((o.counts && o.counts.rules) || 0, 'rule')}${parts.length ? ` (${parts.join(', ')})` : ''}`;
}
function meta(o) {
  const c = o.counts || {};
  const state = String(o.state || '').toLowerCase();
  if (o.kind === 'dictionary') return `Used by ${plural(c.engines || 0, 'engine')} in ${plural(c.rules || 0, 'rule')}`;
  if (o.kind === 'engine') return `${plural(c.dictionaries || 0, 'dictionary', 'dictionaries')} · used by ${plural(c.rules || 0, 'rule')}`;
  if (o.kind === 'rule') return `${o.channel_label || o.channel} · ${state || 'state ?'} · ${plural(c.engines || 0, 'engine')}`;
  if (o.policy) {
    const act = String(o.action || (o.actions || []).join(', ')).toLowerCase().replace(/_/g, ' ');
    return [o.order !== undefined && o.order !== null ? `order ${o.order}` : '', state, act].filter(Boolean).join(' · ');
  }
  if (o.kind === 'url_category') return `${o.custom ? 'Custom' : 'Predefined'} · ${usedIn(o)}`;
  return usedIn(o).replace(/^u/, 'U');
}
function objRow(o) {
  const sev = worst(o);
  return h('li', {}, h('button', { type: 'button', class: 'obj', onclick: () => showDetail(objectKey(o)) },
    h('span', { class: 'nm', text: o.name }),
    h('span', {}, h('span', { class: 'chip kind', text: kindLabel(o.kind) }), ' ', (o.findings || []).length ? h('span', { class: `chip sev-${sev}`, text: plural(o.findings.length, 'finding') }) : null),
    h('span', { class: 'meta', text: meta(o) + (o.pack ? ` · pack ${o.pack}` : '') })));
}
function list(objs, empty) {
  return objs.length ? h('ul', { class: 'list' }, objs.map(objRow)) : h('p', { class: 'empty', text: empty });
}
// The kind filter: every kind the index holds, grouped (DLP, Policies, Objects), with counts.
function kindFilter(objs, onchange) {
  const counts = {};
  objs.forEach(o => { counts[o.kind] = (counts[o.kind] || 0) + 1; });
  const kinds = ((S.index && S.index.kinds) || []).filter(k => counts[k.kind]);
  Object.keys(counts).filter(k => !kinds.some(x => x.kind === k)).forEach(k => kinds.push(Object.assign({ kind: k }, kindInfo(S.index, k))));
  if (S.kind && !counts[S.kind]) S.kind = '';
  const groups = [];
  kinds.forEach(k => { let g = groups.find(x => x.name === k.group); if (!g) groups.push(g = { name: k.group, kinds: [] }); g.kinds.push(k); });
  const sel = h('select', { id: 'kindFilter', 'aria-label': 'Kind', onchange: e => { S.kind = e.target.value; saveSession(); onchange(); } },
    h('option', { value: '', text: `All kinds (${objs.length})` }),
    groups.map(g => h('optgroup', { label: g.name }, g.kinds.map(k => h('option', { value: k.kind, text: `${k.plural} (${counts[k.kind]})` })))));
  sel.value = S.kind;
  return h('label', { class: 'field' }, h('span', { text: 'Kind' }), sel);
}
function moreNote() {
  const more = (S.index && S.index.more) || {};
  const ks = Object.keys(more).filter(k => !S.kind || k === S.kind);
  if (!ks.length) return null;
  return h('p', { class: 'note', text: `${ks.map(k => `${more[k]} more ${inSentence(kindInfo(S.index, k).plural)}`).join(', ')} not shown: DLP-Check keeps the ones with findings and the most used of each kind. Search DLP-Check itself for the rest.` });
}
function viewPage() {
  if (!S.index) return h('p', { class: 'empty', text: 'Read the tenant to see what DLP-Check knows about the objects on this page.' });
  if (S.pageKeys === null) return h('p', { class: 'empty', text: 'No badges on this tab. Open the ZIA admin console (DLP, URL filtering, firewall or other policy pages), and switch the badges on in Settings if you have not.' });
  const all = S.pageKeys.map(k => S.byKey.get(k)).filter(Boolean);
  const out = h('div');
  const run = () => out.replaceChildren(list(all.filter(o => !S.kind || o.kind === S.kind), 'None of the objects DLP-Check read are on this page.'));
  run();
  return h('div', {}, all.length ? kindFilter(all, run) : null, h('div', { style: 'height:8px' }), out);
}
// Kinds in the index's order; rules by their order, everything else by name.
function byKindThenOrder(a, b) {
  const ks = ((S.index && S.index.kinds) || []).map(k => k.kind);
  const ka = ks.indexOf(a.kind), kb = ks.indexOf(b.kind);
  if (ka !== kb) return ka - kb;
  const oa = Number(a.order), ob = Number(b.order);
  if (a.policy && b.policy && a.kind !== 'rule' && Number.isFinite(oa) && Number.isFinite(ob) && oa !== ob) return oa - ob;
  return a.name.localeCompare(b.name);
}
function viewSearch() {
  if (!S.index) return h('p', { class: 'empty', text: 'Read the tenant first.' });
  const all = [...S.byKey.values()];
  const box = h('input', { type: 'search', value: S.query, placeholder: 'Find a rule, category, location or other object', 'aria-label': 'Find an object by name' });
  const out = h('div', { role: 'region', 'aria-label': 'Results' });
  const run = () => {
    const q = box.value.trim().toLowerCase();
    S.query = box.value;
    const objs = all.filter(o => (!S.kind || o.kind === S.kind) && (!q || o.name.toLowerCase().includes(q))).sort(byKindThenOrder);
    out.replaceChildren(h('p', { class: 'note', role: 'status', text: objs.length > 200 ? `${objs.length} match; the first 200 are shown.` : plural(objs.length, 'match', 'matches') }),
      list(objs.slice(0, 200), 'Nothing matches.'), moreNote() || '');
  };
  box.addEventListener('input', run); run();
  setTimeout(() => box.focus(), 0);
  return h('div', {}, kindFilter(all, run), h('div', { style: 'height:8px' }), box, h('div', { style: 'height:8px' }), out);
}
function viewSameName(keys) {
  const objs = keys.map(k => S.byKey.get(k)).filter(Boolean);
  const name = objs.length ? objs[0].name : '';
  return h('div', { class: 'detail' },
    h('button', { type: 'button', onclick: () => { S.focusList = null; render(); }, text: '← Back' }),
    h('p', { class: 'title', text: `${plural(objs.length, 'object')} named “${name}”` }),
    h('p', { class: 'note', text: 'The console shows one name; DLP-Check knows several objects by it. Pick the one you mean.' }),
    list(objs, 'These objects are no longer in the index: read the tenant again.'));
}
function viewStage() {
  const objs = S.stage.map(k => S.byKey.get(k)).filter(o => o && exportable(o));
  const wrap = h('div');
  if (!objs.length) return h('p', { class: 'empty', text: 'Nothing staged. Open a DLP dictionary, engine or rule and choose Stage for export: build a selection across console pages, then export it as a JSON pack or Terraform.' });
  const fmt = S.exportOpts.format;
  const radio = (v, label) => h('label', {}, h('input', { type: 'radio', name: 'fmt', value: v, checked: fmt === v, onchange: () => { S.exportOpts.format = v; } }), label);
  wrap.append(
    h('ul', { class: 'list' }, objs.map(o => h('li', {}, h('div', { class: 'obj' },
      h('span', { class: 'nm', text: o.name }),
      h('button', { type: 'button', 'aria-label': `Remove ${o.name} from the stage`, onclick: () => unstage(objectKey(o)), text: 'Remove' }),
      h('span', { class: 'meta', text: kindLabel(o.kind) + (o.channel_label ? ` · ${o.channel_label}` : '') }))))),
    h('div', { class: 'opts', role: 'group', 'aria-label': 'Export options' },
      radio('json', ' JSON pack'), radio('terraform', ' Terraform'), radio('both', ' JSON pack and Terraform'),
      h('label', {}, h('input', { type: 'checkbox', checked: S.exportOpts.deps, onchange: e => { S.exportOpts.deps = e.target.checked; } }), ' Include what they use')),
    h('div', { class: 'row' },
      h('button', { type: 'button', class: 'primary', id: 'exportGo', onclick: runExport, text: `Export ${plural(objs.length, 'object')}` }),
      h('button', { type: 'button', onclick: () => { S.stage = []; saveSession(); render(); }, text: 'Clear' })),
    h('p', { class: 'note', id: 'exportNote', text: 'Read-only: DLP-Check reads the tenant and writes nothing. Deploying or removing stays in DLP-Check, with write mode and its preview.' }));
  return wrap;
}
function refButtons(kind, names, policy, total) {
  if (!names || !names.length) return h('span', { class: 'note', text: 'none' });
  const extra = total && total > names.length ? h('span', { class: 'note', text: `and ${total - names.length} more` }) : null;
  return h('div', { class: 'refs' }, names.map(n => {
    const o = find(kind, n, policy);
    return o ? h('button', { type: 'button', onclick: () => showDetail(objectKey(o)), 'aria-label': `${n}, ${kindLabel(kind)}`, text: n }) : h('span', { class: 'chip', text: n });
  }), extra);
}
// What a rule uses, one heading per kind (engines, URL categories, locations...).
function usesSections(o) {
  const out = [];
  Object.entries(o.uses || {}).forEach(([key, names]) => {
    const kind = USES_KIND[key] || key;
    const n = (o.counts || {})[key] ?? names.length;
    if (!names.length && key !== 'engines') return;
    out.push(h('h3', { text: `Uses ${inSentence(kindInfo(S.index, kind).plural)} (${n})` }), refButtons(kind, names, null, n));
  });
  return out;
}
// What uses an object, one heading per policy (URL filtering, Cloud Firewall, Inline Web DLP...).
function usedBySections(o) {
  const by = o.used_by || {}, counts = (o.counts && o.counts.by_policy) || {};
  const kinds = (S.index && S.index.policy_kinds) || {};
  const ps = Object.keys(by);
  if (!ps.length) return [h('h3', { text: 'Used by' }), h('p', { class: 'note', text: 'No rule DLP-Check read uses it.' })];
  return ps.flatMap(p => [h('h3', { text: `Used by ${policyLabel(p)} rules (${counts[p] ?? by[p].length})` }),
    refButtons(kinds[p] || 'rule', by[p], p, counts[p])]);
}
// An engine's expression with dictionary names and in one sentence; Copy
// puts the expression as the tenant has it (dictionary ids) on the clipboard.
function engineExpression(o) {
  if (!o.expression && !o.readable) return [h('h3', { text: 'What it matches' }), h('p', { class: 'note', text: 'No expression: a predefined engine, or the tenant gave none.' })];
  const done = h('span', { class: 'note', role: 'status', 'aria-live': 'polite' });
  const copy = () => {
    const ok = () => { done.textContent = 'Copied the expression with dictionary ids.'; };
    const fail = () => { done.textContent = `Copy was blocked; the expression is: ${o.expression}`; };
    try { navigator.clipboard.writeText(o.expression || '').then(ok, fail); } catch (e) { fail(); }
  };
  return [h('h3', { text: 'What it matches' }),
    o.summary ? h('p', { class: 'summary', text: o.summary }) : h('p', { class: 'note', text: 'This expression is not one the app can put in a sentence; the names below are exact.' }),
    h('code', { class: 'expr', title: o.expression || '', text: o.readable || o.expression }),
    h('div', { class: 'row' }, h('button', { type: 'button', onclick: copy, 'aria-label': 'Copy the expression with dictionary ids', text: 'Copy expression' }), done)];
}
function openIn(page) {
  return h('button', { type: 'button', onclick: () => chrome.tabs.create({ url: S.base + PAGES[page].path }), text: page === 'home' ? 'Open DLP-Check' : `Open ${PAGES[page].label} in DLP-Check` });
}
// The object's workspace notes (tags, to-dos, comments) as the app keeps
// them for this tenant: read-only here (GET); they are written in the app.
function notesSection(o) {
  const box = h('div', { class: 'notes', 'aria-live': 'polite' }, h('p', { class: 'note', text: 'Loading the notes…' }));
  const tenant = (S.index && S.index.tenant_label) || '';
  if (!tenant) { box.replaceChildren(h('p', { class: 'note', text: 'Read the tenant to see its notes.' })); return box; }
  api(S.base, '/api/workspace/notes?' + new URLSearchParams({ tenant, kind: o.kind, ref: objectKey(o) }).toString()).then(d => {
    const n = d && d.note;
    if (!n) { box.replaceChildren(h('p', { class: 'note', text: 'No tags or notes. Add them on the object\'s card in the app (Find anything, Ctrl+J).' })); return; }
    const open = (n.todos || []).filter(t => !t.done);
    box.replaceChildren(
      (n.tags || []).length ? h('div', { class: 'refs' }, n.tags.map(t => h('span', { class: 'chip', text: t }))) : null,
      open.length ? h('ul', { class: 'list' }, open.map(t => h('li', { class: 'meta', text: `To-do: ${t.text}` }))) : null,
      (n.comments || []).slice(-3).map(c => h('p', { class: 'note', text: `${c.by || ''}: ${c.text}` })),
      h('p', { class: 'note', text: `${plural(open.length, 'open to-do')}, ${plural((n.comments || []).length, 'comment')}. Edit them in the app.` }));
  }).catch(e => { box.replaceChildren(h('p', { class: 'note', text: `Notes not available: ${e.message}` })); });
  return box;
}
function viewDetail(o) {
  const key = objectKey(o);
  const staged = S.stage.includes(key);
  const kv = [];
  const add = (k, v) => { if (v !== undefined && v !== null && v !== '') kv.push(h('dt', { text: k }), h('dd', {}, v)); };
  add('Kind', kindLabel(o.kind) + ((o.kind === 'dictionary' || o.kind === 'url_category') && o.custom === false ? ' (predefined)' : o.kind === 'url_category' ? ' (custom)' : ''));
  if (o.kind === 'rule') { add('Channel', o.channel_label || o.channel); add('State', String(o.state || '').toLowerCase()); add('Action', String(o.action || '').toLowerCase()); }
  if (o.policy && o.kind !== 'rule') {
    add('Policy', o.policy_label || policyLabel(o.policy));
    if (o.type) add('Type', String(o.type).toLowerCase().replace(/_/g, ' '));
    add('Order', o.order);
    add('State', String(o.state || '').toLowerCase());
    add('Action', String(o.action || (o.actions || []).join(', ')).toLowerCase().replace(/_/g, ' '));
  }
  if (o.kind === 'dictionary' && o.type) add('Type', String(o.type).toLowerCase().replace(/_/g, ' '));
  if (o.kind === 'url_category' && o.id) add('ID', o.id);
  if (o.kind === 'file_type') { add('Type', o.category); add('API name', o.id); }
  if (exportable(o)) add('Created by', o.pack ? `policy pack ${o.pack}` : 'not by a DLP-Check pack');
  const by = o.used_by || {};
  const sections = [];
  if (o.kind === 'dictionary') sections.push(h('h3', { text: `Used by engines (${o.counts.engines || 0})` }), refButtons('engine', by.engines),
    h('h3', { text: `Reaches rules (${o.counts.rules || 0})` }), refButtons('rule', by.rules));
  else if (o.kind === 'engine') sections.push(...engineExpression(o), ...usesSections(o), h('h3', { text: `Used by rules (${o.counts.rules || 0})` }), refButtons('rule', by.rules));
  else if (o.kind === 'rule' || o.policy) sections.push(...usesSections(o));
  else sections.push(...usedBySections(o));
  const findings = (o.findings || []).map(f => h('div', { class: `finding sev-${f.severity}` }, h('span', { class: `chip sev-${f.severity}`, text: f.severity }), ' ', f.text));
  const sub = o.kind === 'rule' && o.parent_id != null;
  const actions = [];
  if (exportable(o)) {
    actions.push(sub ? h('span', { class: 'note', text: 'An endpoint sub-rule is exported with its parent rule.' })
      : h('button', { type: 'button', class: staged ? '' : 'primary', onclick: () => (staged ? unstage(key) : stage(key)), text: staged ? 'Remove from the stage' : 'Stage for export' }));
  }
  if (SHADOW_KINDS.includes(o.kind)) actions.push(openIn('shadow'));
  actions.push(openIn('home'));
  return h('div', { class: 'detail' },
    h('button', { type: 'button', onclick: () => { S.focus = null; render(); }, text: '← Back' }),
    h('p', { class: 'title', text: o.name }),
    h('dl', { class: 'kv' }, kv),
    o.name_derived ? h('p', { class: 'note', text: `Named after its ID: the API gives predefined categories no display name, so the console may spell it differently.` }) : null,
    ...sections,
    h('h3', { text: 'Findings' }), findings.length ? findings : h('p', { class: 'note', text: 'None.' }),
    h('h3', { text: 'Tags and notes' }), notesSection(o),
    exportable(o) ? null : h('p', { class: 'note', text: 'Export from tenant covers DLP objects only; open DLP-Check for this one.' }),
    h('div', { class: 'row' }, actions));
}
function render() {
  document.querySelectorAll('.seg [role="tab"]').forEach(t => t.setAttribute('aria-selected', String(t.dataset.v === S.view && !S.focus && !S.focusList)));
  $('stageCount').textContent = String(S.stage.length);
  const o = S.focus ? S.byKey.get(S.focus) : null;
  const v = o ? viewDetail(o) : S.focusList ? viewSameName(S.focusList) : S.view === 'search' ? viewSearch() : S.view === 'stage' ? viewStage() : viewPage();
  $('view').replaceChildren(v);
}
function showDetail(key) { S.focus = key; render(); }
function stage(key) { const o = S.byKey.get(key); if (o && exportable(o) && !S.stage.includes(key)) S.stage.push(key); saveSession(); render(); }
function unstage(key) { S.stage = S.stage.filter(k => k !== key); saveSession(); render(); }

// ── Export the stage (read-only job in DLP-Check) ────────────────────
async function runExport() {
  const objs = S.stage.map(k => S.byKey.get(k)).filter(Boolean);
  const dictionaries = objs.filter(o => o.kind === 'dictionary' && o.id != null).map(o => String(o.id));
  const engines = objs.filter(o => o.kind === 'engine' && o.id != null).map(o => String(o.id));
  const rules = {};
  objs.filter(o => o.kind === 'rule' && o.id != null && o.parent_id == null && o.channel).forEach(o => { (rules[o.channel] = rules[o.channel] || []).push(String(o.id)); });
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
  t.addEventListener('click', async () => { S.view = t.dataset.v; S.focus = null; S.focusList = null; if (S.view === 'page') await refreshPage(); render(); });
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
  if (area === 'session' && changes.focus && changes.focus.newValue) { focusFrom(changes.focus.newValue); render(); }
});
chrome.tabs.onActivated.addListener(async () => { if (S.view === 'page' && !S.focus && !S.focusList) { await refreshPage(); render(); } });

(async () => {
  await loadSession();
  const up = await connect();
  noteRead();
  if (up) await refreshPage();
  render();
})();
