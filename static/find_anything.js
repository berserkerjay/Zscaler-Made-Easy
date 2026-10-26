// ── Find anything (Ctrl/Cmd+J, or / outside a text field) ──────────────
// One search box over everything the app knows, as you type:
//   - the app's pages and actions (the explain.js catalogue: name, what,
//     group), so "how do I export to terraform" finds the Terraform hand-off;
//   - glossary terms (static/glossary.js and the help page's glossary), with
//     the plain meaning shown inline;
//   - the tenant's objects from the last console index this server read for
//     the signed-in tenant (GET /api/console-index/cached: never a tenant
//     read). Typing never reads the tenant; only "Load tenant objects" does,
//     with the Scope page's selection (POST /api/console-index, read-only);
//   - the findings of the assessment loaded in this tab (or the tab that
//     opened this one), and the to-dos written on objects (workspace notes).
// Matching is plain-language and forgiving: stop words are ignored, typos
// are tolerated (one or two letters wrong or swapped) and a small synonym
// map links words people use for the same thing ("block" and "deny", "tf"
// and "terraform", "dlp" and "data loss").
// An object's card shows what it uses, what uses it, its findings, links to
// the pages that act on it, and its workspace notes (tags, to-dos and
// comments, kept by the app per tenant: /api/workspace/notes).
//
// The matching functions are pure and exported for node tests
// (tests/test_find_anything.py); the dialog only runs in a browser.
(function () {
  'use strict';

  // ── Plain-language matching (pure) ─────────────────────────────────
  const STOP = new Set(('a an the i me my we our you your it its this that these those to of for from in on at by with and or ' +
    'how do does did can could should would will what which where when who why is are be been am was were get got see show ' +
    'find want need way use using please there here into about some any all just like make let').split(' '));
  // Words people use for the same thing. Each group is one meaning; a word
  // may sit in more than one group.
  const SYNONYMS = [
    ['block', 'blocks', 'blocked', 'deny', 'denied', 'stop', 'prevent'],
    ['allow', 'allowed', 'permit'],
    ['dlp', 'data loss', 'data loss prevention', 'data protection'],
    ['tf', 'terraform', 'iac', 'infrastructure as code', 'hcl'],
    ['export', 'exports', 'download', 'hand off', 'handoff', 'extract'],
    ['import', 'upload'],
    ['rule', 'rules', 'policy', 'policies'],
    ['dictionary', 'dictionaries', 'dict', 'word list', 'pattern'],
    ['engine', 'engines'],
    ['ssl', 'tls', 'https', 'decrypt', 'decryption'],
    ['zcc', 'client connector'],
    ['url', 'urls', 'website', 'site', 'sites', 'domain', 'web'],
    ['bypass', 'bypasses', 'skip', 'exemption', 'exception'],
    ['unused', 'orphan', 'dead', 'never used'],
    ['shadowed', 'shadow', 'hidden', 'never match', 'unreachable'],
    ['todo', 'todos', 'to do', 'task', 'tasks'],
    ['pac', 'proxy auto config'],
    ['fw', 'firewall'],
    ['cac', 'cloud app control', 'app control'],
    ['ftc', 'file type control', 'file type'],
    ['fp', 'false positive', 'false positives', 'noise', 'noisy'],
    ['audit', 'history', 'who changed'],
    ['compliance', 'regulatory', 'framework', 'frameworks'],
    ['pack', 'packs', 'policy pack', 'baseline', 'template'],
    ['casb', 'saas', 'saas security'],
    ['incident', 'incidents', 'alert', 'alerts'],
    ['deploy', 'push', 'roll out'],
    ['remove', 'delete', 'uninstall', 'undo', 'rollback', 'roll back'],
    ['zpa', 'private access'],
    ['zia', 'internet access'],
    ['assessment', 'scan', 'check up', 'score'],
    ['tenant', 'org', 'organisation', 'organization', 'customer'],
    ['sign in', 'login', 'log in', 'authenticate', 'connect', 'credentials'],
    ['report', 'word', 'excel', 'pdf', 'spreadsheet'],
    ['monitor', 'monitor only', 'watch'],
    ['bulk', 'mass', 'batch'],
    ['migrate', 'migration', 'convert'],
  ];

  function norm(s) {
    let t = String(s == null ? '' : s).toLowerCase();
    try { t = t.normalize('NFD').replace(/[̀-ͯ]/g, ''); } catch (e) { /* old engine */ }
    return t.replace(/[^a-z0-9]+/g, ' ').trim();
  }
  const words = s => (norm(s) ? norm(s).split(' ') : []);

  // Optimal string alignment distance (Levenshtein plus one swap of two
  // neighbouring letters, "terrafrom" -> "terraform" is 1), or max+1 when
  // it is more than `max`.
  function osa(a, b, max) {
    if (a === b) return 0;
    if (Math.abs(a.length - b.length) > max) return max + 1;
    const n = a.length, m = b.length;
    let p2 = null, p1 = new Array(m + 1), cur;
    for (let j = 0; j <= m; j++) p1[j] = j;
    for (let i = 1; i <= n; i++) {
      cur = new Array(m + 1); cur[0] = i;
      let low = cur[0];
      for (let j = 1; j <= m; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        let v = Math.min(p1[j] + 1, cur[j - 1] + 1, p1[j - 1] + cost);
        if (p2 && i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, p2[j - 2] + 1);
        cur[j] = v; if (v < low) low = v;
      }
      if (low > max) return max + 1;
      p2 = p1; p1 = cur;
    }
    return p1[m];
  }
  const maxTypos = len => (len >= 8 ? 2 : len >= 3 ? 1 : 0);

  // The synonyms of one normalized word or phrase (itself excluded).
  const SYN_INDEX = new Map();
  SYNONYMS.forEach(g => {
    const ng = g.map(norm);
    ng.forEach(w => { const s = SYN_INDEX.get(w) || new Set(); ng.forEach(x => { if (x !== w) s.add(x); }); SYN_INDEX.set(w, s); });
  });
  function synonymsOf(w) { return Array.from(SYN_INDEX.get(norm(w)) || []); }

  // A query as terms: each term is the word the person typed and its
  // synonyms (a phrase such as "data loss" is one term). Stop words go,
  // unless nothing else is left.
  function parseQuery(q) {
    const all = words(q);
    let ws = all.filter(w => !STOP.has(w));
    if (!ws.length) ws = all;
    const terms = [];
    for (let i = 0; i < ws.length; i++) {
      // The longest known phrase starting here ("data loss prevention").
      let phrase = null, used = 1;
      for (let k = Math.min(4, ws.length - i); k >= 2; k--) {
        const p = ws.slice(i, i + k).join(' ');
        if (SYN_INDEX.has(p)) { phrase = p; used = k; break; }
      }
      const w = phrase || ws[i];
      terms.push({ text: w, alts: [{ w, syn: false }].concat(synonymsOf(w).map(s => ({ w: s, syn: true }))) });
      i += used - 1;
    }
    return terms;
  }

  // How well one alternative matches one field (0..1).
  function matchField(alt, f) {
    const w = alt.w;
    if (w.indexOf(' ') >= 0) return (' ' + f.text + ' ').indexOf(' ' + w + ' ') >= 0 ? 1 : 0;
    let best = 0;
    const typos = alt.syn ? 0 : maxTypos(w.length);
    for (let i = 0; i < f.words.length; i++) {
      const x = f.words[i];
      if (x === w) return 1;
      if (x.length > w.length && x.startsWith(w)) { best = Math.max(best, w.length >= 3 ? 0.85 : 0.6); continue; }
      if (typos && best < 0.7) {
        if (osa(w, x, typos) <= typos) best = Math.max(best, 0.7);
        else if (x.length > w.length && osa(w, x.slice(0, w.length), 1) <= 1) best = Math.max(best, 0.45);
      }
    }
    if (best < 0.5 && w.length >= 4 && f.text.indexOf(w) >= 0) best = 0.5;
    return best;
  }

  // An item ready to search: its fields as normalized text and words, each with a weight.
  function prepare(item) {
    item._f = (item.fields || []).filter(f => f && f[0]).map(f => { const text = norm(f[0]); return { text, words: text ? text.split(' ') : [], weight: f[1] }; });
    item._title = norm(item.title);
    return item;
  }

  const TYPE_RANK = { Page: 0, Finding: 1, 'To-do': 2, Term: 4 };
  function scoreItem(item, terms, qn) {
    let score = 0, matched = 0, inTitle = 0;
    const title = item._f[0];
    for (const t of terms) {
      let best = 0, titled = false;
      for (const alt of t.alts) {
        for (const f of item._f) {
          const m = matchField(alt, f) * f.weight * (alt.syn ? 0.85 : 1);
          if (m > best) best = m;
          if (f === title && m >= f.weight * 0.6) titled = true;
        }
      }
      if (best > 0) { matched++; score += best; }
      if (titled) inTitle++;
    }
    if (!matched) return 0;
    if (matched < Math.ceil(terms.length * 0.5)) return 0;
    if (matched === terms.length) score *= 1.25;
    // A short title that the query covers beats a long one that mentions it.
    if (inTitle && title && title.words.length) score += 4 * Math.min(1, inTitle / title.words.length);
    if (qn && item._title === qn) score += 12;
    else if (qn && item._title.startsWith(qn)) score += 6;
    return score;
  }

  // The best `limit` items for a query, best first; an empty query gives nothing.
  function search(items, q, limit) {
    const terms = parseQuery(q);
    if (!terms.length) return [];
    const qn = norm(q);
    const out = [];
    for (const it of items) {
      if (!it._f) prepare(it);
      const s = scoreItem(it, terms, qn);
      if (s > 0) out.push({ item: it, score: s });
    }
    out.sort((a, b) => (b.score - a.score) || ((TYPE_RANK[a.item.type] ?? 3) - (TYPE_RANK[b.item.type] ?? 3)) || String(a.item.title).localeCompare(String(b.item.title)));
    return out.slice(0, limit || 50).map(x => x.item);
  }

  const firstSentence = s => { const t = String(s || ''); const m = /^(.{20,220}?[.!?])(\s|$)/.exec(t); return m ? m[1] : t.slice(0, 220); };

  // The app's pages and actions, from the explain.js catalogue.
  function pageItems(X, order) {
    X = X || {};
    const keys = (order || []).filter(k => X[k]).concat(Object.keys(X).filter(k => (order || []).indexOf(k) < 0));
    return keys.map(k => {
      const x = X[k];
      return prepare({ type: 'Page', id: 'page:' + k, key: k, title: x.name, line: firstSentence(x.what), group: x.group, href: x.href || '',
        fields: [[x.name, 10], [k, 6], [x.group, 2], [x.what, 3], [x.get, 1.5], [x.when, 1]] });
    });
  }
  // Glossary terms: Simple mode's plain words first, then the help page's.
  function termItems(simple, dlp) {
    const seen = new Set(), out = [];
    Object.keys(simple || {}).forEach(k => {
      const g = simple[k]; if (!g || !g.term) return;
      seen.add(norm(g.term));
      out.push(prepare({ type: 'Term', id: 'term:' + norm(g.term), title: g.term, line: g.def, def: g.def, fields: [[g.term, 10], [g.def, 2]] }));
    });
    (dlp || []).forEach(pair => {
      if (!pair || seen.has(norm(pair[0]))) return;
      seen.add(norm(pair[0]));
      out.push(prepare({ type: 'Term', id: 'term:' + norm(pair[0]), title: pair[0], line: pair[1], def: pair[1], fields: [[pair[0], 10], [pair[1], 2]] }));
    });
    return out;
  }
  function kindInfo(index, kind) {
    const k = ((index && index.kinds) || []).find(x => x.kind === kind);
    return k || { label: String(kind || 'object').replace(/_/g, ' ').replace(/^./, c => c.toUpperCase()), group: 'Objects' };
  }
  const objKey = o => o.key || `${o.kind}:${o.kind === 'rule' ? `${o.channel}:` : ''}${o.name}`;
  const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + 's')}`;
  function objMeta(index, o) {
    const c = o.counts || {};
    const state = String(o.state || '').toLowerCase();
    const f = (o.findings || []).length ? ` · ${plural(o.findings.length, 'finding')}` : '';
    if (o.kind === 'dictionary') return `Used by ${plural(c.engines || 0, 'engine')} in ${plural(c.rules || 0, 'rule')}${f}`;
    if (o.kind === 'engine') return `${plural(c.dictionaries || 0, 'dictionary', 'dictionaries')} · used by ${plural(c.rules || 0, 'rule')}${f}`;
    if (o.kind === 'rule') return `${o.channel_label || o.channel || 'DLP'} · ${state || 'state not read'} · ${plural(c.engines || 0, 'engine')}${f}`;
    if (o.policy) return [((index && index.policy_labels) || {})[o.policy] || o.policy, o.order != null ? `order ${o.order}` : '', state,
      String(o.action || (o.actions || []).join(', ')).toLowerCase().replace(/_/g, ' ')].filter(Boolean).join(' · ') + f;
    return `Used in ${plural(c.rules || 0, 'rule')}${f}`;
  }
  // The tenant's objects from a console index.
  function objectItems(index, tagsByKey) {
    return ((index && index.objects) || []).filter(o => o && o.name).map(o => {
      const k = kindInfo(index, o.kind);
      const key = objKey(o);
      const tags = (tagsByKey && tagsByKey[key]) || [];
      return prepare({ type: k.label, id: 'obj:' + key, key, obj: o, title: o.name, line: objMeta(index, o), tags,
        fields: [[o.name, 10], [`${k.label} ${String(o.kind).replace(/_/g, ' ')} ${o.channel_label || ''} ${((index.policy_labels || {})[o.policy]) || ''}`, 2],
          [tags.join(' '), 5], [(o.findings || []).map(x => `${x.short || ''} ${x.text || ''}`).join(' '), 1.5]] });
    });
  }
  const PILL = { FAIL: 'Action required', REVIEW: 'Needs review' };
  // The findings that need action in an assessment result.
  function findingItems(report) {
    return ((report && report.checks) || []).filter(c => c && !c.out_of_scope && (c.status === 'FAIL' || c.status === 'REVIEW')).map(c => {
      const pl = c.plain || {};
      return prepare({ type: 'Finding', id: 'finding:' + c.id, key: String(c.id), check: c, title: c.label || c.id,
        line: `${PILL[c.status]} · ${c.section || ''} · [${c.id}]`,
        fields: [[c.label, 10], [String(c.id), 8], [c.section, 2], [`${pl.found || ''} ${pl.do || ''}`, 2]] });
    });
  }
  // Open to-dos from workspace notes.
  function todoItems(notes) {
    const out = [];
    (notes || []).forEach(n => (n.todos || []).filter(t => !t.done).forEach(t => {
      out.push(prepare({ type: 'To-do', id: 'todo:' + n.id + ':' + t.id, note: n, todo: t, title: t.text, line: `On ${n.label || n.ref}${(n.tags || []).length ? ' · ' + n.tags.join(', ') : ''}`,
        fields: [[t.text, 8], [n.label || n.ref, 4], [(n.tags || []).join(' '), 4]] }));
    }));
    return out;
  }

  const core = { norm, osa, parseQuery, synonymsOf, search, prepare, pageItems, termItems, objectItems, findingItems, todoItems, objKey, SYNONYMS, STOP };
  if (typeof window === 'undefined') {
    if (typeof module !== 'undefined' && module.exports) module.exports = core;
    return;
  }
  window.DLP_FIND_CORE = core;
  if (window.DLP_FIND) return;   // loaded twice: the first one stays

  // ── Where things are ───────────────────────────────────────────────
  const onHome = () => (location.pathname.replace(/\/+$/, '') || '/') === '/';
  const opener = () => { try { return window.opener && !window.opener.closed && window.opener.location.origin === location.origin ? window.opener : null; } catch (e) { return null; } };
  // Who holds the sign-in and the scope: this page (the assessment page) or the one that opened it.
  function home() {
    if (typeof window.migrateCredBody === 'function') return window;
    const op = opener();
    return op && typeof op.migrateCredBody === 'function' ? op : null;
  }
  // The toolbar opener for each catalogue entry on the assessment page,
  // so a page opens exactly as its toolbar button opens it.
  const OPENERS = {
    help: ['openHelpTab'], simple: ['openSimpleMode'], dataflow: ['openDataFlowTab'], zpa: ['openZpaTab'], path: ['openPathAnalyzerTab'],
    motion: ['openFlowAnimatorTab'], live: ['openLiveFeedTab'], insights: ['openInsightsTab'], shadow: ['openShadowRulesTab'],
    efficacy: ['openToolTab', 'efficacy'], fleet: ['openFleetTab'], health: ['openDetectionHealthTab'], digest: ['openDigestTab'],
    packs: ['openDlpPacksModal'], queue: ['openQueueTab'], operations: ['openOperationsTab'], terraform: ['openToolTab', 'terraform'],
    vendormigrate: ['openVendorMigrateTab'], migration: ['_gdGoMigration'], evalall: ['openEvalAllTab'], bestpractices: ['openToolTab', 'bestpractices'],
    exports: ['openExportsTab'], advanced: ['openAdvancedTab'], updates: ['openToolTab', 'updates'], audit: ['openAuditTimelineTab'],
    logs: ['openLogAnalyzerTab'], zcc: ['openToolTab', 'zcc'], todo: ['openTodoTab'],
    refportfolio: ['openReferenceTab', 'data-security-portfolio-framework'], refai: ['openReferenceTab', 'ai-security-framework'],
    refgenai: ['openReferenceTab', 'genai-security-framework'], refmachine: ['openReferenceTab', 'framework-machine'],
    dsarchitect: ['openReferenceTab', 'data-security-architect'],
  };
  // Open a catalogue entry. On the assessment page: as its toolbar button
  // does (most open a new tab that reads the sign-in from this one). On a
  // report page: the page itself in this tab (the assessment tab stays this
  // tab's opener); a dialog or tool of the assessment page opens there.
  function goPage(key) {
    const X = window.DLP_EXPLAIN || {}, x = X[key];
    if (!x) return;
    if (onHome()) {
      const o = OPENERS[key];
      if (o && typeof window[o[0]] === 'function') { window[o[0]].apply(window, o.slice(1)); return; }
      if (!x.href || x.href === '/') { window.scrollTo({ top: 0 }); return; }
      const w = window.open(x.href, '_blank'); if (!w) location.href = x.href;
      return;
    }
    if (x.href && x.href !== '/' && x.href.indexOf('/report/view') !== 0) { location.href = x.href; return; }
    const op = opener();
    if (op && op.DLP_FIND && (location.pathname !== '/')) {
      try { op.DLP_FIND.go(key); op.focus(); return; } catch (e) { /* below */ }
    }
    location.href = '/?find=' + encodeURIComponent(key);
  }

  // ── Data ───────────────────────────────────────────────────────────
  const S = { open: false, items: [], results: [], active: -1, index: null, indexNote: '', notes: [], notesTenant: '', loading: false,
    lastFocus: null, glossaryAsked: false, cachedAsked: false, view: 'list', timer: null };
  function report() {
    try { if (typeof window.__assessmentReport === 'function') { const r = window.__assessmentReport(); if (r) return r; } } catch (e) { /* none */ }
    const op = opener();
    try { if (op && typeof op.__assessmentReport === 'function') { const r = op.__assessmentReport(); if (r) return r; } } catch (e) { /* none */ }
    try { const raw = sessionStorage.getItem('zassess_last_results'); return raw ? JSON.parse(raw) : null; } catch (e) { return null; }
  }
  function profileId() {
    const h = home();
    try { return (h && h.GD && h.GD.profile) || ''; } catch (e) { return ''; }
  }
  // Which tenant a note belongs to: the loaded index's, else the sign-in on
  // the assessment page (no secret), else the server's own tenant.
  function tenantRef() {
    if (S.index && S.index.tenant_label) return { tenant: S.index.tenant_label };
    const h = home();
    if (h) {
      try {
        const b = h.migrateCredBody() || {};
        if (b.profile_id) return { profile_id: b.profile_id };
        if (b.vanity_domain || b.auth_method === 'legacy') return { vanity_domain: b.vanity_domain || '', cloud: b.cloud || '', auth_method: b.auth_method || '' };
      } catch (e) { /* below */ }
    }
    return {};
  }
  const qs = o => Object.keys(o).filter(k => o[k] !== undefined && o[k] !== '').map(k => `${encodeURIComponent(k)}=${encodeURIComponent(o[k])}`).join('&');
  async function getJson(url, init) {
    const r = await fetch(url, Object.assign({ cache: 'no-store' }, init || {}));
    let d = null; try { d = await r.json(); } catch (e) { d = null; }
    if (!r.ok) { const det = d && d.detail; throw new Error(typeof det === 'string' ? det : (det && (det.message || det.cause)) || `HTTP ${r.status}`); }
    return d;
  }
  function tagsByKey() {
    const out = {};
    (S.notes || []).forEach(n => { if ((n.tags || []).length) out[n.ref] = n.tags; });
    return out;
  }
  function rebuild() {
    S.items = pageItems(window.DLP_EXPLAIN, window.DLP_EXPLAIN_ORDER)
      .concat(findingItems(report()))
      .concat(objectItems(S.index, tagsByKey()))
      .concat(todoItems(S.notes))
      .concat(termItems(window.SIMPLE_GLOSSARY, window.DLP_GLOSSARY));
    if (S.open && S.view === 'list') runSearch();   // a card stays open while its notes change
  }
  function loadGlossary() {
    if (S.glossaryAsked || window.SIMPLE_GLOSSARY) return;
    S.glossaryAsked = true;
    const s = document.createElement('script');
    s.src = '/static/glossary.js';
    s.onload = rebuild;
    document.head.appendChild(s);
  }
  async function loadCached() {
    if (S.cachedAsked) return;
    S.cachedAsked = true;
    try {
      const d = await getJson('/api/console-index/cached?' + qs({ profile_id: profileId() }));
      if (d && d.index) { S.index = d.index; }
    } catch (e) { /* no index kept */ }
    noteIndex();
    await loadNotes();
    rebuild();
  }
  async function loadNotes() {
    const ref = tenantRef();
    try {
      const d = await getJson('/api/workspace/notes?' + qs(ref));
      S.notes = (d && d.notes) || []; S.notesTenant = (d && d.tenant) || '';
    } catch (e) { S.notes = []; S.notesTenant = ''; }
  }
  function ago(t) {
    if (!t) return '';
    const m = Math.round((Date.now() / 1000 - t) / 60);
    return m < 1 ? 'just now' : m < 60 ? `${m} min ago` : `${Math.round(m / 60)} h ago`;
  }
  function noteIndex() {
    const x = S.index;
    S.indexNote = x ? `Tenant objects: ${x.tenant_label || 'tenant'}, ${plural((x.objects || []).length, 'object')}, read ${ago(x.cached_at || x.read_at)}.`
      : 'No tenant objects loaded yet. Load tenant objects reads the tenant once (read-only, only what is in scope on the Scope page); typing never does.';
    const n = document.getElementById('faIndexNote'); if (n) n.textContent = S.indexNote;
    const b = document.getElementById('faLoad'); if (b) b.textContent = x ? 'Read tenant objects again' : 'Load tenant objects';
  }
  // The Scope page's selection, from the assessment page or as it publishes it.
  function scopeSelection() {
    const readJson = (k, f) => { try { const raw = localStorage.getItem(k); const v = raw ? JSON.parse(raw) : f; return v == null ? f : v; } catch (e) { return f; } };
    const declared = st => { const out = {}; Object.entries(st || {}).forEach(([id, v]) => { const c = v && typeof v === 'object' ? v.choice : v; if (c === 'zscaler' || c === 'alternative') out[id] = c; }); return out; };
    const h = home();
    let scopes = null, channels = null;
    try { if (h && typeof h.getSelectedScopes === 'function') scopes = h.getSelectedScopes(); } catch (e) { scopes = null; }
    try { if (h && typeof h.__dbChannelScope === 'function') channels = declared(h.__dbChannelScope()); } catch (e) { channels = null; }
    if (!Array.isArray(scopes)) { const lv = readJson('zassess_scopes_live_v1', null); scopes = lv && Array.isArray(lv.scopes) ? lv.scopes : null; }
    if (!Array.isArray(scopes)) return { scopes: [], channels: {}, from_page: false };
    if (!channels) channels = declared(readJson('zassess_channels_v1', {}));
    return { scopes: scopes.map(String), channels, from_page: true };
  }
  async function loadTenant() {
    if (S.loading) return;
    const b = document.getElementById('faLoad'), st = document.getElementById('faStatus');
    S.loading = true; if (b) b.disabled = true;
    say('Reading the tenant objects (read-only, only what is in scope)…');
    const h = home();
    let creds = {};
    try { creds = h ? (h.migrateCredBody() || {}) : { profile_id: profileId() }; } catch (e) { creds = {}; }
    try {
      const idx = await getJson('/api/console-index', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({}, creds, scopeSelection(), { refresh: !!S.index })) });
      S.index = idx;
      noteIndex();
      await loadNotes();
      rebuild();
      say(`${plural((idx.objects || []).length, 'tenant object')} loaded.`);
    } catch (e) {
      say(`Could not load the tenant objects: ${e.message}`);
      if (st) st.textContent = `Could not load the tenant objects: ${e.message}`;
    } finally { S.loading = false; if (b) b.disabled = false; }
  }

  // ── DOM helpers (values always set as text) ────────────────────────
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (v === undefined || v === null || v === false) return;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : String(v));
    });
    kids.flat().forEach(c => { if (c !== null && c !== undefined && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c))); });
    return el;
  }
  function say(t) {
    const live = document.getElementById('faLive'); if (!live) return;
    live.textContent = ''; setTimeout(() => { live.textContent = t; }, 30);
  }

  const CSS = `.fa-back[hidden]{display:none}
.fa-back{position:fixed;inset:0;z-index:10001;background:color-mix(in srgb,var(--bg) 55%,transparent);display:flex;align-items:flex-start;justify-content:center;padding:8vh 16px 16px}
.fa-dlg{width:min(680px,100%);max-height:84vh;display:flex;flex-direction:column;background:var(--card-solid,var(--card));color:var(--text);border:1px solid var(--border-strong,var(--border));border-radius:var(--r-lg,12px);overflow:hidden;font-size:var(--fs-callout,0.875rem)}
.fa-head{display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:1px solid var(--border)}
.fa-head h2{margin:0;font-size:var(--fs-headline,0.9375rem);font-weight:600;flex:0 0 auto}
.fa-input{flex:1 1 auto;min-width:0;min-height:var(--ctl-md,36px);padding:0 10px;border:1px solid var(--border);border-radius:var(--r-md,10px);background:var(--well);color:var(--text);font:inherit;font-size:var(--fs-body,0.9375rem)}
.fa-input:focus-visible,.fa-dlg button:focus-visible,.fa-dlg a:focus-visible,.fa-dlg input:focus-visible,.fa-dlg textarea:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.fa-body:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.fa-x,.fa-btn{min-height:var(--ctl-sm,28px);padding:0 10px;border:1px solid var(--border);border-radius:var(--r-sm,6px);background:var(--well);color:var(--text);font:inherit;cursor:pointer}
.fa-btn:disabled{opacity:.55;cursor:default}
.fa-body{flex:1 1 auto;overflow:auto;min-height:80px}
.fa-list{list-style:none;margin:0;padding:4px}
.fa-opt{display:grid;grid-template-columns:auto 1fr;gap:2px 10px;padding:8px 10px;border-radius:var(--r-md,10px);cursor:pointer;align-items:baseline}
.fa-opt[aria-selected="true"]{background:var(--accent-tint,color-mix(in srgb,var(--accent) 16%,transparent));outline:1px solid var(--accent)}
.fa-type{grid-row:span 2;font-size:var(--fs-caption,0.6875rem);font-weight:600;color:var(--dim);border:1px solid var(--border);border-radius:var(--r-pill,999px);padding:1px 8px;white-space:nowrap;align-self:start;margin-top:2px}
.fa-title{font-weight:600;overflow-wrap:anywhere}
.fa-line{color:var(--dim);font-size:var(--fs-footnote,0.75rem);overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.fa-empty,.fa-hint{color:var(--dim);padding:12px 14px;margin:0}
.fa-foot{border-top:1px solid var(--border);padding:8px 12px;display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;color:var(--dim);font-size:var(--fs-footnote,0.75rem)}
.fa-foot .fa-note{flex:1 1 260px}
.fa-keys{flex:1 1 100%}
.fa-card{padding:12px 14px}
.fa-card h3{margin:6px 0 2px;font-size:var(--fs-title3,1rem)}
.fa-card h4{margin:12px 0 4px;font-size:var(--fs-subhead,0.8125rem);color:var(--dim);font-weight:600}
.fa-card p{margin:4px 0}
.fa-refs{display:flex;flex-wrap:wrap;gap:4px}
.fa-chip{display:inline-flex;align-items:center;gap:4px;border:1px solid var(--border);border-radius:var(--r-pill,999px);padding:1px 8px;font-size:var(--fs-footnote,0.75rem);background:var(--well);color:var(--text)}
button.fa-chip{cursor:pointer;font:inherit;font-size:var(--fs-footnote,0.75rem)}
.fa-sev-high{border-color:var(--fail);background:color-mix(in srgb,var(--fail) 18%,transparent)}
.fa-sev-medium{border-color:var(--warn);background:color-mix(in srgb,var(--warn) 18%,transparent)}
.fa-sev-low{border-color:var(--border-strong,var(--border))}
.fa-row{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;align-items:center}
.fa-notes{margin-top:10px;border-top:1px solid var(--border);padding-top:6px}
.fa-notes ul{list-style:none;margin:0;padding:0}
.fa-notes li{display:flex;gap:8px;align-items:flex-start;padding:4px 0;border-bottom:1px solid var(--border)}
.fa-notes li .grow{flex:1 1 auto;overflow-wrap:anywhere}
.fa-notes input[type=text],.fa-notes textarea{flex:1 1 200px;min-width:0;min-height:var(--ctl-sm,28px);padding:4px 8px;border:1px solid var(--border);border-radius:var(--r-sm,6px);background:var(--well);color:var(--text);font:inherit}
.fa-done{text-decoration:line-through;color:var(--dim)}
.fa-err{color:var(--fail)}
.fa-open-btn{margin-left:auto}
@media (max-width:600px){.fa-keys{display:none}.fa-back{padding:8px}.fa-dlg{max-height:calc(100vh - 16px)}.fa-head h2{display:none}}`;

  // ── The dialog ─────────────────────────────────────────────────────
  let dlg = null, input = null, listEl = null, bodyEl = null;
  function build() {
    if (dlg) return;
    if (!document.getElementById('faStyle')) { const st = document.createElement('style'); st.id = 'faStyle'; st.textContent = CSS; document.head.appendChild(st); }
    input = h('input', { id: 'faInput', class: 'fa-input', type: 'text', role: 'combobox', 'aria-expanded': 'false', 'aria-controls': 'faList',
      'aria-autocomplete': 'list', 'aria-describedby': 'faKeys', autocomplete: 'off', spellcheck: 'false',
      placeholder: 'Search pages, terms, rules, dictionaries, findings…', 'aria-label': 'Find anything' });
    listEl = h('ul', { id: 'faList', class: 'fa-list', role: 'listbox', 'aria-label': 'Results' });
    // The results scroll: a focusable region, so the keyboard can scroll a long
    // detail view in every browser (WCAG 2.1.1), not only where scrollers are focusable.
    bodyEl = h('div', { class: 'fa-body', id: 'faBody', tabindex: '0', role: 'region', 'aria-label': 'Find anything results' }, listEl);
    const box = h('div', { class: 'fa-dlg', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'faTitle' },
      h('div', { class: 'fa-head' }, h('h2', { id: 'faTitle', text: 'Find anything' }), input,
        h('button', { type: 'button', class: 'fa-x', 'aria-label': 'Close Find anything', onclick: close, text: 'Close' })),
      bodyEl,
      h('div', { class: 'fa-foot' },
        h('span', { class: 'fa-note', id: 'faIndexNote', text: S.indexNote }),
        h('button', { type: 'button', class: 'fa-btn', id: 'faLoad', onclick: loadTenant, text: 'Load tenant objects' }),
        h('span', { class: 'fa-note', id: 'faStatus', role: 'status', 'aria-live': 'polite' }),
        h('span', { class: 'fa-keys', id: 'faKeys', text: '↑ ↓ to move, Enter to open, Esc to close. Ctrl+J or / opens this from any page.' })),
      h('div', { id: 'faLive', class: 'sr-only', role: 'status', 'aria-live': 'polite', style: 'position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap' }));
    dlg = h('div', { class: 'fa-back', id: 'faBack', hidden: true }, box);
    dlg.addEventListener('mousedown', e => { if (e.target === dlg) close(); });
    dlg.addEventListener('keydown', onKey);
    input.addEventListener('input', () => { clearTimeout(S.timer); S.timer = setTimeout(runSearch, 50); });
    document.body.appendChild(dlg);
    noteIndex();
  }
  function focusables() {
    return Array.from(dlg.querySelectorAll('button, [href], input, textarea, select, [tabindex]:not([tabindex="-1"])'))
      .filter(el => !el.disabled && el.offsetParent !== null);
  }
  function onKey(e) {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); return; }
    if (e.key === 'Tab') {
      const f = focusables(); if (!f.length) return;
      const i = f.indexOf(document.activeElement);
      if (e.shiftKey && (i <= 0)) { e.preventDefault(); f[f.length - 1].focus(); }
      else if (!e.shiftKey && i === f.length - 1) { e.preventDefault(); f[0].focus(); }
      return;
    }
    if (e.target !== input || S.view !== 'list') return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (!S.results.length) return;
      const d = e.key === 'ArrowDown' ? 1 : -1;
      setActive((S.active + d + S.results.length) % S.results.length);
    } else if (e.key === 'Home' && e.ctrlKey) { e.preventDefault(); if (S.results.length) setActive(0); }
    else if (e.key === 'End' && e.ctrlKey) { e.preventDefault(); if (S.results.length) setActive(S.results.length - 1); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      const it = S.results[S.active >= 0 ? S.active : 0];
      if (it) openItem(it);
    }
  }
  function setActive(i) {
    S.active = i;
    Array.from(listEl.children).forEach((li, j) => li.setAttribute('aria-selected', String(j === i)));
    const li = listEl.children[i];
    if (li) { input.setAttribute('aria-activedescendant', li.id); li.scrollIntoView({ block: 'nearest' }); } else input.removeAttribute('aria-activedescendant');
  }
  const SUGGEST = ['assessment', 'connect', 'path', 'shadow', 'packs', 'terraform', 'exports', 'todo', 'help'];
  function runSearch() {
    if (!dlg) return;
    S.view = 'list';
    bodyEl.replaceChildren(listEl);
    const q = input.value.trim();
    let res;
    if (!q) {
      const byKey = {}; S.items.forEach(it => { if (it.type === 'Page') byKey[it.key] = it; });
      res = SUGGEST.map(k => byKey[k]).filter(Boolean);
    } else res = search(S.items, q, 50);
    S.results = res; S.active = res.length ? 0 : -1;
    listEl.replaceChildren(...res.map((it, i) => h('li', { id: `faOpt${i}`, class: 'fa-opt', role: 'option', 'aria-selected': String(i === 0),
      onclick: () => openItem(it), onmousemove: () => { if (S.active !== i) setActive(i); } },
    h('span', { class: 'fa-type', text: it.type }), h('span', { class: 'fa-title', text: it.title }), h('span', { class: 'fa-line', text: it.line || '' }))));
    input.setAttribute('aria-expanded', String(res.length > 0));
    if (res.length) input.setAttribute('aria-activedescendant', 'faOpt0'); else input.removeAttribute('aria-activedescendant');
    if (!res.length) {
      bodyEl.append(h('p', { class: 'fa-empty', text: S.index ? `Nothing matches “${q}”. Try another word, or fewer words.`
        : `Nothing matches “${q}”. Tenant objects are not loaded yet: Load tenant objects below to search rules, dictionaries and other objects too.` }));
    } else if (!q) {
      bodyEl.prepend(h('p', { class: 'fa-hint', text: 'Type what you want to do or find: a page ("export to Terraform"), a word ("engine"), a rule or dictionary name, or a finding. Typos are fine.' }));
    }
    say(q ? (res.length ? `${plural(res.length, 'result')}. The first is ${res[0].type}: ${res[0].title}.` : 'No results.') : '');
  }

  function open(query) {
    build();
    if (S.open) { input.focus(); if (query) { input.value = query; runSearch(); } return; }
    S.lastFocus = document.activeElement;
    S.open = true;
    dlg.hidden = false;
    loadGlossary();
    rebuild();
    input.value = query || '';
    runSearch();
    input.focus();
    input.select();
    loadCached();
  }
  function close() {
    if (!S.open) return;
    S.open = false;
    dlg.hidden = true;
    S.view = 'list';
    const back = S.lastFocus;
    S.lastFocus = null;
    if (back && document.contains(back) && typeof back.focus === 'function') { try { back.focus(); } catch (e) { /* gone */ } }
  }

  // ── Opening a result ───────────────────────────────────────────────
  function openItem(it) {
    if (it.type === 'Page') { if (it.key === 'find') return; close(); goPage(it.key); return; }
    if (it.type === 'Term') { showCard(termCard(it)); return; }
    if (it.type === 'Finding') { showCard(findingCard(it.check)); return; }
    if (it.type === 'To-do') {
      const o = S.index && (S.index.objects || []).find(x => objKey(x) === it.note.ref);
      showCard(o ? objectCard(o) : noteOnlyCard(it.note));
      return;
    }
    if (it.obj) showCard(objectCard(it.obj));
  }
  function showCard(card) {
    S.view = 'card';
    input.setAttribute('aria-expanded', 'false'); input.removeAttribute('aria-activedescendant');
    const back = h('button', { type: 'button', class: 'fa-btn', onclick: () => { runSearch(); input.focus(); }, text: '← Back to results' });
    bodyEl.replaceChildren(h('div', { class: 'fa-card', role: 'region', 'aria-label': 'Details' }, back, card));
    bodyEl.scrollTop = 0;
    back.focus();
  }
  function termCard(it) {
    return h('div', {}, h('h3', { text: it.title }), h('p', { text: it.def }),
      h('div', { class: 'fa-row' }, h('a', { class: 'fa-btn', href: '/help#glossary', target: '_blank', rel: 'noopener', text: 'Every term on the help page' })));
  }
  const pageBtn = (key, label) => {
    const x = (window.DLP_EXPLAIN || {})[key]; if (!x) return null;
    return h('button', { type: 'button', class: 'fa-btn', onclick: () => { close(); goPage(key); }, text: label || `Open ${x.name}` });
  };
  // The pages that act on an object of this kind.
  function pagesFor(o) {
    const k = o.kind;
    const out = [];
    if (['rule', 'url_rule', 'cac_rule', 'ssl_rule', 'firewall_rule'].indexOf(k) >= 0) out.push('shadow');
    if (k === 'ssl_rule') out.push('sslflow');
    if (k === 'dictionary' || k === 'engine') out.push('efficacy');
    if (['url_rule', 'cac_rule', 'ssl_rule', 'firewall_rule', 'ftc_rule', 'rule', 'url_category'].indexOf(k) >= 0) out.push('operations');
    if (k === 'url_category' || o.policy) out.push('exports');
    if (k === 'rule' || k === 'engine' || k === 'dictionary') out.push('packs');
    if (['location', 'location_group', 'group', 'department', 'url_category'].indexOf(k) >= 0) out.push('path');
    return out;
  }
  function refButtons(kind, names) {
    if (!names || !names.length) return h('p', { class: 'fa-hint', style: 'padding:0', text: 'None.' });
    return h('div', { class: 'fa-refs' }, names.map(n => {
      const o = S.index && (S.index.objects || []).find(x => x.name === n && (x.kind === kind || !kind));
      return o ? h('button', { type: 'button', class: 'fa-chip', onclick: () => showCard(objectCard(o)), 'aria-label': `${n}, ${kindInfo(S.index, o.kind).label}`, text: n })
        : h('span', { class: 'fa-chip', text: n });
    }));
  }
  const USES_KIND = { engines: 'engine', dictionaries: 'dictionary', rules: 'rule' };
  function objectCard(o) {
    const k = kindInfo(S.index, o.kind);
    const parts = [h('h3', { text: o.name }), h('p', {}, h('span', { class: 'fa-chip', text: k.label }), ' ', objMeta(S.index, o))];
    Object.entries(o.uses || {}).forEach(([key, names]) => {
      if (!(names || []).length) return;
      const kind = USES_KIND[key] || key;
      parts.push(h('h4', { text: `Uses ${kindInfo(S.index, kind).label.toLowerCase().replace(/^dlp /, 'DLP ')}s (${(o.counts || {})[key] ?? names.length})` }), refButtons(kind, names));
    });
    const by = o.used_by || {};
    const policyKinds = (S.index && S.index.policy_kinds) || {}, labels = (S.index && S.index.policy_labels) || {};
    Object.entries(by).forEach(([key, names]) => {
      if (!(names || []).length) return;
      const kind = USES_KIND[key] || policyKinds[key] || '';
      const what = USES_KIND[key] ? key : `${labels[key] || key} rules`;
      parts.push(h('h4', { text: `Used by ${what} (${names.length})` }), refButtons(kind, names));
    });
    if (!Object.keys(by).some(x => (by[x] || []).length) && o.kind !== 'rule' && !o.policy) parts.push(h('h4', { text: 'Used by' }), h('p', { class: 'fa-hint', style: 'padding:0', text: 'No rule that was read uses it.' }));
    parts.push(h('h4', { text: 'Findings' }));
    const fs = o.findings || [];
    parts.push(fs.length ? h('ul', { style: 'margin:0;padding-left:1.1rem' }, fs.map(f => h('li', {}, h('span', { class: `fa-chip fa-sev-${f.severity}`, text: f.severity }), ' ', f.text)))
      : h('p', { class: 'fa-hint', style: 'padding:0', text: 'None.' }));
    const pages = pagesFor(o).map(key => pageBtn(key)).filter(Boolean);
    if (pages.length) parts.push(h('h4', { text: 'Open it in' }), h('div', { class: 'fa-row' }, pages));
    parts.push(notesBlock({ kind: o.kind, ref: objKey(o), label: `${k.label}: ${o.name}`, href: (window.DLP_EXPLAIN && window.DLP_EXPLAIN[pagesFor(o)[0]] || {}).href || '' }));
    return h('div', {}, parts);
  }
  function findingCard(c) {
    const pl = c.plain || {};
    const dl = h('dl', { style: 'margin:6px 0' });
    [['What we found', pl.found], ['What it means for the business', pl.means], ['What to do', pl.do], ['Once fixed', pl.outcome]].forEach(([t, v]) => {
      if (v) dl.append(h('dt', { style: 'font-weight:600;color:var(--dim);font-size:var(--fs-footnote)', text: t }), h('dd', { style: 'margin:0 0 6px', text: v }));
    });
    const row = h('div', { class: 'fa-row' });
    if (onHome()) row.append(h('button', { type: 'button', class: 'fa-btn', text: 'Show it in the findings', onclick: () => { close(); showFinding(c.id); } }));
    else row.append(pageBtn('results', 'Open the assessment results'));
    return h('div', {}, h('h3', { text: c.label || c.id }), h('p', {}, h('span', { class: 'fa-chip', text: PILL[c.status] || c.status }), ` ${c.section || ''} · [${c.id}]`),
      dl.children.length ? dl : h('p', { text: c.detail || '' }), row,
      notesBlock({ kind: 'finding', ref: String(c.id), label: `Finding [${c.id}] ${c.label || ''}`.trim(), href: '/report/view' }));
  }
  function showFinding(id) {
    const rows = Array.from(document.querySelectorAll('.check-item'));
    const row = rows.find(r => { const s = r.querySelector('.check-id'); return s && s.textContent === `[${id}]`; });
    if (!row) { if (typeof window.openResultsTab === 'function') window.openResultsTab(); return; }
    row.scrollIntoView({ block: 'center' });
    row.setAttribute('tabindex', '-1'); row.focus();
  }
  function noteOnlyCard(n) {
    return h('div', {}, h('h3', { text: n.label || n.ref }), h('p', { class: 'fa-hint', style: 'padding:0', text: 'This object is not in the loaded tenant objects. Load tenant objects to see what it uses and what uses it.' }),
      n.href ? h('div', { class: 'fa-row' }, h('a', { class: 'fa-btn', href: n.href, text: 'Open the page it belongs to' })) : null,
      notesBlock({ kind: n.kind, ref: n.ref, label: n.label, href: n.href }));
  }

  // ── Workspace notes on an object (tags, to-dos, comments) ──────────
  function notesBlock(target) {
    const wrap = h('section', { class: 'fa-notes', 'aria-label': 'Tags and notes' }, h('h4', { text: 'Tags, to-dos and comments' }),
      h('p', { class: 'fa-hint', style: 'padding:0', text: 'Loading the notes…' }));
    renderNotes(wrap, target);
    return wrap;
  }
  async function renderNotes(wrap, target) {
    const ref = tenantRef();
    let note = null, tenant = '', err = '';
    try {
      const d = await getJson('/api/workspace/notes?' + qs(Object.assign({}, ref, { kind: target.kind, ref: target.ref })));
      note = d.note; tenant = d.tenant;
    } catch (e) { err = e.message; }
    const status = h('p', { class: 'fa-hint', role: 'status', 'aria-live': 'polite', style: 'padding:0' });
    const write = async (payload, okMsg) => {
      status.textContent = 'Saving…';
      try {
        const d = await getJson('/api/workspace/notes', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(Object.assign({}, ref, { kind: target.kind, ref: target.ref, label: target.label || '', href: target.href || '' }, payload)) });
        note = d.note;
        await loadNotes(); rebuild();
        draw(); status.textContent = okMsg;
      } catch (e) { status.textContent = ''; status.append(h('span', { class: 'fa-err', text: `Not saved: ${e.message}` })); }
    };
    const field = (label, id, multiline) => {
      const el = h(multiline ? 'textarea' : 'input', Object.assign({ id, 'aria-label': label, placeholder: label }, multiline ? { rows: '2' } : { type: 'text' }));
      return el;
    };
    function draw() {
      const n = note || { tags: [], todos: [], comments: [] };
      const tagIn = field('Add a tag', 'faTagIn'), todoIn = field('Add a to-do', 'faTodoIn'), comIn = field('Add a comment', 'faComIn', true);
      const onEnter = (el, fn) => el.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); fn(); } });
      const addTag = () => { const v = tagIn.value.trim(); if (v) write({ action: 'add_tag', tag: v }, `Tag “${v}” added.`); };
      const addTodo = () => { const v = todoIn.value.trim(); if (v) write({ action: 'add_todo', text: v }, 'To-do added.'); };
      const addCom = () => { const v = comIn.value.trim(); if (v) write({ action: 'add_comment', text: v }, 'Comment added.'); };
      onEnter(tagIn, addTag); onEnter(todoIn, addTodo); onEnter(comIn, addCom);
      wrap.replaceChildren(h('h4', { text: `Tags, to-dos and comments${tenant ? ` (${tenant})` : ''}` }),
        h('div', { class: 'fa-refs', 'aria-label': 'Tags', role: 'group' }, (n.tags || []).length ? n.tags.map(t => h('span', { class: 'fa-chip' }, t,
          h('button', { type: 'button', class: 'fa-x', style: 'min-height:20px;padding:0 4px', 'aria-label': `Remove tag ${t}`, onclick: () => write({ action: 'remove_tag', tag: t }, `Tag “${t}” removed.`), text: '×' })))
          : h('span', { class: 'fa-hint', style: 'padding:0', text: 'No tags yet.' })),
        h('div', { class: 'fa-row' }, tagIn, h('button', { type: 'button', class: 'fa-btn', onclick: addTag, text: 'Add tag' })),
        h('h4', { text: 'To-dos' }),
        (n.todos || []).length ? h('ul', {}, n.todos.map(t => {
          const id = `faTodo${t.id}`;
          return h('li', {}, h('input', { type: 'checkbox', id, checked: !!t.done, onchange: e => write({ action: 'set_todo', item_id: t.id, done: e.target.checked }, e.target.checked ? 'Marked done.' : 'Marked open.') }),
            h('label', { for: id, class: `grow${t.done ? ' fa-done' : ''}`, text: t.text }),
            h('button', { type: 'button', class: 'fa-x', 'aria-label': `Delete to-do ${t.text}`, onclick: () => write({ action: 'delete_todo', item_id: t.id }, 'To-do deleted.'), text: 'Delete' }));
        })) : h('p', { class: 'fa-hint', style: 'padding:0', text: 'No to-dos on this object. Open ones show on the To-do list page.' }),
        h('div', { class: 'fa-row' }, todoIn, h('button', { type: 'button', class: 'fa-btn', onclick: addTodo, text: 'Add to-do' })),
        h('h4', { text: 'Comments' }),
        (n.comments || []).length ? h('ul', {}, n.comments.map(c => h('li', {}, h('span', { class: 'grow' }, c.text, h('br'), h('span', { class: 'fa-hint', style: 'padding:0', text: `${c.by || ''} · ${String(c.at || '').replace('T', ' ').slice(0, 16)}` })),
          h('button', { type: 'button', class: 'fa-x', 'aria-label': 'Delete this comment', onclick: () => write({ action: 'delete_comment', item_id: c.id }, 'Comment deleted.'), text: 'Delete' }))))
          : h('p', { class: 'fa-hint', style: 'padding:0', text: 'No comments yet.' }),
        h('div', { class: 'fa-row' }, comIn, h('button', { type: 'button', class: 'fa-btn', onclick: addCom, text: 'Add comment' })),
        status,
        h('p', { class: 'fa-hint', style: 'padding:0', text: 'Kept by Zscaler Made Easy on this computer for this tenant, with who wrote each one. Nothing is written to the tenant.' }));
    }
    if (err) {
      wrap.replaceChildren(h('h4', { text: 'Tags, to-dos and comments' }), h('p', { class: 'fa-hint', style: 'padding:0', text: `Notes are not available: ${err}` }));
      return;
    }
    draw();
  }

  // ── Shortcuts and the Find button ──────────────────────────────────
  function typing(el) {
    if (!el) return false;
    const t = (el.tagName || '').toLowerCase();
    return t === 'input' || t === 'textarea' || t === 'select' || el.isContentEditable;
  }
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && String(e.key).toLowerCase() === 'j') {
      e.preventDefault();
      if (S.open) close(); else open();
      return;
    }
    if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey && !S.open && !typing(e.target)) {
      e.preventDefault(); open();
    }
  }, true);
  function addButton() {
    if (onHome() || document.getElementById('faOpenBtn')) return;
    const bar = document.querySelector('.rp-bar');
    if (!bar) return;
    bar.appendChild(h('button', { type: 'button', class: 'rp-btn fa-open-btn', id: 'faOpenBtn', 'aria-keyshortcuts': 'Control+J Meta+J /',
      'aria-label': 'Find anything: pages, terms, tenant objects and findings (Ctrl+J)', title: 'Find anything (Ctrl+J or /)', onclick: () => open(), text: 'Find' }));
  }
  function start() {
    addButton();
    // A report page without an assessment tab sends a tool here: /?find=<key>.
    if (onHome()) {
      const k = new URLSearchParams(location.search).get('find');
      if (k && window.DLP_EXPLAIN && window.DLP_EXPLAIN[k]) {
        try { history.replaceState(null, '', '/'); } catch (e) { /* keep the address */ }
        setTimeout(() => goPage(k), 400);
      }
    }
  }
  window.DLP_FIND = { open, close, go: goPage, isOpen: () => S.open };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
