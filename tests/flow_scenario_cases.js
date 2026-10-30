/* Offline, individually identified frontend behavior cases. No dependency installs. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {El, parse} = require('./path_motion_dom.js');
const ROOT = path.resolve(__dirname, '..');
const CASES = new Map();
function test(id, fn) {
  assert(!CASES.has(id), 'Duplicate case ID: ' + id);
  CASES.set(id, fn);
}
const clone = value => JSON.parse(JSON.stringify(value));
const flush = () => new Promise(resolve => setImmediate(resolve));
const tick = async () => { await flush(); await flush(); };
function models() { return require(path.join(ROOT, 'static/flow_anim.js')); }
function scenario() { return require(path.join(ROOT, 'static/flow_scenario.js')); }

// Parse the actual page controls. Missing IDs are errors, so a markup/control
// regression cannot accidentally pass because a stub invented the element.
function browser(options) {
  options = options || {};
  const html = fs.readFileSync(path.join(ROOT, 'static/report_motion.html'), 'utf8');
  const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].at(-1)[1];
  const doc = new El('#document');
  // The markup up to the body's first script (the head's glass.js runs before paint and holds no markup).
  parse(html.slice(0, html.indexOf('<script', html.indexOf('<body'))), doc);
  const all = () => doc.all();
  const nativeMatches = El.prototype.matches;
  const listeners = {};
  const requests = [], render = [], storageWrites = [];
  const responseQueues = new Map();
  const timers = new Map();
  let now = 0, nextTimer = 0;
  const decorate = el => {
    if (el.__browserDecorated) return el;
    el.__browserDecorated = true;
    let value;
    Object.defineProperty(el, 'value', {
      get() {
        if (value !== undefined) return value;
        if (el.tag === 'select') {
          const choices = el.children.filter(c => c.tag === 'option');
          const selected = choices.find(c => Object.hasOwn(c.attrs, 'selected')) || choices[0];
          return selected ? selected.attrs.value || selected.textContent : '';
        }
        return el.attrs.value || '';
      },
      set(v) { value = String(v); },
    });
    Object.defineProperty(el, 'className', {get: () => el.attrs.class || '', set: v => {el.attrs.class = String(v);}});
    Object.defineProperty(el, 'firstChild', {get: () => el.children[0] || null});
    Object.defineProperty(el, 'lastChild', {get: () => el.children.at(-1) || null});
    ['hidden', 'checked', 'disabled', 'required'].forEach(key => { el[key] = Object.hasOwn(el.attrs, key); });
    el.focus = () => { doc.activeElement = el; };
    el.insertBefore = (child, before) => {
      if (child.parent) child.remove();
      child.parent = el;
      const index = el.children.indexOf(before);
      if (index < 0) el.children.push(child); else el.children.splice(index, 0, child);
      return child;
    };
    el.removeChild = child => { child.remove(); return child; };
    el.replaceChildren = (...children) => { el.children = []; children.forEach(c => el.appendChild(c)); };
    el.matches = sel => {
      const attrs = [...sel.matchAll(/\[([^\]=]+)(?:=["']?([^\]"']+)["']?)?\]/g)];
      const simple = sel.replace(/\[[^\]]+\]/g, '') || '*';
      return (simple === '*' || nativeMatches.call(el, simple)) && attrs.every(m => Object.hasOwn(el.attrs, m[1]) && (m[2] === undefined || el.attrs[m[1]] === m[2]));
    };
    el.checkValidity = () => !el.required || !!el.value.trim();
    el.reportValidity = el.checkValidity;
    return el;
  };
  all().forEach(decorate);
  doc.getElementById = id => all().find(e => e.id === id) || null;
  doc.createElement = tag => decorate(new El(tag));
  doc.createElementNS = (_ns, tag) => decorate(new El(tag));
  const get = id => {
    const el = doc.getElementById(id);
    assert(el, 'Page has no control #' + id);
    return decorate(el);
  };
  const FA = Object.assign({}, models());
  function player(kind, host, model, opts) {
    const record = {kind, host: host.id, model, opts: opts || {}, plays: 0, steps: 0, resets: 0, destroyed: false, pushed: []};
    render.push(record);
    return {
      destroy() { record.destroyed = true; }, play() { record.plays++; return Promise.resolve(); },
      step() { record.steps++; }, pause() {}, running() { return false; }, replay() {}, reset() { record.resets++; record.pushed = []; if (record.opts.onReset) record.opts.onReset(); },
      clear() { record.pushed = []; }, push(m) { record.pushed.push(m); },
    };
  }
  ['drill', 'hopPlayer', 'live', 'graph', 'steps', 'trafficPath', 'listFlow'].forEach(kind => { FA[kind] = (host, model, opts) => player(kind, host, model, opts); });
  const storage = Object.assign({}, options.storage || {});
  const location = {hash: options.hash || '#live', search: ''};
  const success = data => ({ok: true, status: 200, json: async () => clone(data)});
  const context = {
    FA, FS: fs.existsSync(path.join(ROOT, 'static/flow_scenario.js')) ? scenario() : undefined,
    document: doc, console, URL, URLSearchParams, AbortController, Date, Promise, TextEncoder,
    location, history: {replaceState(_a, _b, hash) { location.hash = hash; }},
    localStorage: {getItem: key => Object.hasOwn(storage, key) ? storage[key] : null,
      setItem: (key, value) => { storageWrites.push({key, value}); }, removeItem: key => {delete storage[key];}},
    setTimeout(fn, ms) { const id = ++nextTimer; timers.set(id, {at: now + Number(ms || 0), fn}); return id; },
    clearTimeout(id) { timers.delete(id); },
    setInterval() { throw new Error('Unexpected interval; polling must have one cancellable chain'); },
    clearInterval() {},
    addEventListener(event, fn) { (listeners[event] = listeners[event] || []).push(fn); },
    removeEventListener(event, fn) { listeners[event] = (listeners[event] || []).filter(f => f !== fn); },
    fetch(url, init) {
      const entry = {url, init: init || {}, body: init && init.body ? JSON.parse(init.body) : null};
      requests.push(entry);
      const queue = responseQueues.get(url) || [];
      if (queue.length) return queue.shift()(entry);
      if (url === '/api/tenant-profiles') return Promise.resolve(success({profiles: options.profiles || []}));
      if (url === '/api/live-feed') return Promise.resolve(success({incidents: [], next_since: 'cursor', stats: {}, errors: [], read_at: '2026-10-05T12:00:00Z', tenant_label: 'Fixture tenant'}));
      throw new Error('No fixture queued for ' + url);
    },
  };
  context.window = context;
  context.opener = options.opener || null;
  vm.createContext(context);
  // Load the actual module in its browser environment as well as CommonJS;
  // this catches accidental missing browser global exports.
  if (fs.existsSync(path.join(ROOT, 'static/flow_scenario.js'))) vm.runInContext(fs.readFileSync(path.join(ROOT, 'static/flow_scenario.js'), 'utf8'), context);
  vm.runInContext(script, context);
  return {
    get, context, requests, render, storage, storageWrites, timers,
    async event(id, type) { const el = get(id); const calls = (el.listeners[type] || []).map(f => f({type, target: el, preventDefault() {}})); await tick(); return calls; },
    async click(id) { return this.event(id, 'click'); },
    async change(id, value) { get(id).value = value; return this.event(id, 'change'); },
    async windowEvent(event, data) { (listeners[event] || []).forEach(f => f(data || {})); await tick(); },
    async navigate(hash) { location.hash = '#' + hash; await this.windowEvent('hashchange'); },
    queue(url, data, status) { const q = responseQueues.get(url) || []; q.push(() => Promise.resolve({ok: !status || status < 400, status: status || 200, json: async () => clone(data)})); responseQueues.set(url, q); },
    reject(url, message) { const q = responseQueues.get(url) || []; q.push(() => Promise.reject(new Error(message))); responseQueues.set(url, q); },
    defer(url) {
      let resolve, reject;
      const promise = new Promise((yes, no) => {resolve = yes; reject = no;});
      const q = responseQueues.get(url) || []; q.push(() => promise); responseQueues.set(url, q);
      return {resolve: data => resolve(success(data)), reject};
    },
    async advance(ms) {
      const end = now + ms;
      for (;;) {
        const due = [...timers.entries()].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        timers.delete(due[0]); now = due[1].at; due[1].fn(); await tick();
      }
      now = end;
    },
    polls() { return requests.filter(r => r.url === '/api/live-feed'); },
    newest(kind, host) { return render.filter(r => r.kind === kind && (!host || r.host === host)).at(-1); },
  };
}

const input = patch => Object.assign({channel: 'web', destination: 'https://example.test/upload', operation: 'upload', network: 'off', platform: 'windows', file_type: 'txt', corpus: 'Synthetic account reference TEST-123'}, patch || {});
const evidence = patch => Object.assign({tenant_key: 'tenant-a', scope_key: 'scope-a', scenario_id: 'scenario-a', configuration_id: 'configuration-a'}, patch || {});
const incident = patch => Object.assign({id: 'event-a', channel: 'web', created_at: '2026-10-05T12:00:00Z', rules: ['Rule A'], engines: ['Engine A'], dictionaries: [{name: 'Synthetic dictionary', count: 3}], enforcement: 'enforced', host: 'example.test'}, patch || {});
const response = patch => Object.assign({schema_version: 1, provenance: 'simulated', scenario: Object.assign(evidence(), {id: 'scenario-a', channel: 'web', destination: 'example.test', operation: 'upload', mode: 'simulated'}), stages: [
  {key: 'url', label: 'URL Filtering', status: 'pass', source: 'configuration', object_id: 'url-7', object_name: 'Allowed destinations', detail: 'Destination rule matches.'},
  {key: 'ssl', label: 'SSL Inspection', status: 'unverified', detail: 'Decryption telemetry unavailable.'},
  {key: 'ftc', label: 'File Type Control', status: 'conditional', detail: 'File metadata is synthetic.'},
  {key: 'dlp', label: 'DLP', status: 'conditional', detail: 'Local dictionary simulation only.'},
], limitations: ['Event-time enforcement is not verified.']}, patch || {});
const badInput = (patch, fragment) => assert(scenario().validateInput(input(patch)).some(e => e.toLowerCase().includes(fragment)), JSON.stringify(scenario().validateInput(input(patch))));
const goodInput = patch => assert.deepEqual(scenario().validateInput(input(patch)), []);
const rejectResponse = value => assert.throws(() => scenario().responseModel(value));

// Input semantics: preserve the content being tested while normalizing only
// metadata, and reject inputs that would change or obscure the scenario.
test('INPUT-01-channel-whitespace-is-normalized', () => assert.equal(scenario().normalizeInput(input({channel: ' EMAIL '})).channel, 'email'));
test('INPUT-02-corpus-whitespace-is-preserved', () => assert.equal(scenario().normalizeInput(input({corpus: '  exact\r\ncontent\t '})).corpus, '  exact\r\ncontent\t '));
test('INPUT-03-file-extension-dot-and-case-normalized', () => assert.equal(scenario().normalizeInput(input({file_type: '.XLSX'})).file_type, 'xlsx'));
test('INPUT-04-destination-is-trimmed-without-rewriting-path', () => assert.equal(scenario().normalizeInput(input({destination: '  https://Example.test/Case?Value=YES  '})).destination, 'https://Example.test/Case?Value=YES'));
test('INPUT-05-default-device-context-is-explicit', () => { const r = scenario().normalizeInput({}); assert.equal(r.channel, 'web'); assert.equal(r.platform, 'windows'); assert.equal(r.network, 'off'); });
test('INPUT-06-operation-reaches-normalized-request', () => assert.equal(scenario().normalizeInput(input({operation: 'download'})).operation, 'download'));
test('INPUT-07-normalization-does-not-mutate-form-state', () => { const r = input({file_type: '.PDF'}), before = clone(r); scenario().normalizeInput(r); assert.deepEqual(r, before); });
test('INPUT-08-credentials-are-not-copied-into-scenario', () => { const r = scenario().normalizeInput(input({password: 'do-not-copy', client_secret: 'do-not-copy', access_token: 'do-not-copy'})); assert(!JSON.stringify(r).includes('do-not-copy')); });
test('INPUT-09-scenario-id-is-trimmed', () => assert.equal(scenario().normalizeInput(input({scenario_id: ' scenario-42 '})).scenario_id, 'scenario-42'));
test('INPUT-10-null-input-does-not-crash', () => { assert.equal(scenario().normalizeInput(null).corpus, ''); assert(scenario().validateInput(null).length >= 2); });

test('VALIDATE-01-complete-web-scenario-is-valid', () => goodInput());
test('VALIDATE-02-endpoint-scenario-is-not-forced-through-url-controls', () => goodInput({channel: 'endpoint', destination: 'usb', operation: 'copy'}));
test('VALIDATE-03-email-address-is-a-valid-destination', () => goodInput({channel: 'email', destination: 'recipient@example.test', operation: 'send'}));
test('VALIDATE-04-saas-application-is-a-valid-destination', () => goodInput({channel: 'saas', destination: 'sharepoint', operation: 'upload'}));
test('VALIDATE-05-unsupported-channel-is-rejected', () => badInput({channel: 'firewall'}, 'channel'));
test('VALIDATE-06-empty-content-is-rejected', () => badInput({corpus: ''}, 'content'));
test('VALIDATE-07-whitespace-only-content-is-rejected', () => badInput({corpus: '\r\n\t '}, 'content'));
test('VALIDATE-08-web-destination-is-required', () => badInput({destination: ' '}, 'destination'));
test('VALIDATE-09-content-byte-boundary-is-inclusive', () => goodInput({corpus: 'x'.repeat(262144)}));
test('VALIDATE-10-content-over-byte-boundary-is-rejected', () => badInput({corpus: 'x'.repeat(262145)}, '256'));
test('VALIDATE-11-multibyte-content-uses-utf8-limit', () => badInput({corpus: '😀'.repeat(65537)}, '256'));
test('VALIDATE-12-multibyte-content-at-byte-boundary-is-valid', () => goodInput({corpus: '😀'.repeat(65536)}));
test('VALIDATE-13-overlong-destination-is-rejected', () => badInput({destination: 'x'.repeat(2049)}, 'destination'));
test('VALIDATE-14-destination-control-character-is-rejected', () => badInput({destination: 'https://example.test/\u0000secret'}, 'characters'));
test('VALIDATE-15-destination-whitespace-injection-is-rejected', () => badInput({destination: 'https://example.test/ HTTP/1.1'}, 'characters'));
test('VALIDATE-16-destination-markup-is-rejected', () => badInput({destination: '<script>alert(1)</script>'}, 'characters'));
test('VALIDATE-17-file-type-path-traversal-is-rejected', () => badInput({file_type: '../pdf'}, 'file type'));
test('VALIDATE-18-file-type-length-is-bounded', () => badInput({file_type: 'a'.repeat(33)}, 'file type'));
test('VALIDATE-19-unknown-network-cannot-select-a-route', () => badInput({network: 'trusted-maybe'}, 'network'));
test('VALIDATE-20-unsupported-platform-is-rejected', () => badInput({platform: 'router'}, 'platform'));
test('VALIDATE-21-operation-markup-is-rejected', () => badInput({operation: '<upload>'}, 'operation'));
test('VALIDATE-22-operation-length-is-bounded', () => badInput({operation: 'x'.repeat(65)}, 'operation'));
test('VALIDATE-23-errors-are-collected-together', () => assert(scenario().validateInput(input({channel: 'invalid', corpus: '', destination: 'two words', network: 'invalid', platform: 'invalid', file_type: '../bad'})).length >= 6));

// Tenant and scope identity: stable key order must not create duplicate
// sessions, and materially different tenant/scope selections must reset one.
test('CONTEXT-01-scope-order-is-not-identity', () => { const f = scenario().contextKey; assert.equal(f('a', {scopes: ['dlp','zcc']}), f('a', {scopes: ['zcc','dlp']})); });
test('CONTEXT-02-channel-object-order-is-not-identity', () => { const f = scenario().contextKey; assert.equal(f('a', {channels: {web:'zscaler',email:'alternative'}}), f('a', {channels: {email:'alternative',web:'zscaler'}})); });
test('CONTEXT-03-object-and-scalar-channel-choice-agree', () => { const f = scenario().contextKey; assert.equal(f('a', {channels: {web:{choice:'zscaler'}}}), f('a', {channels:{web:'zscaler'}})); });
test('CONTEXT-04-different-tenants-are-isolated', () => assert.notEqual(scenario().contextKey('profile:a', {}), scenario().contextKey('profile:b', {})));
test('CONTEXT-05-different-service-scopes-are-isolated', () => assert.notEqual(scenario().contextKey('a', {scopes:['dlp']}), scenario().contextKey('a', {scopes:['zcc']})));
test('CONTEXT-06-alternative-vendor-choice-changes-identity', () => assert.notEqual(scenario().contextKey('a', {channels:{web:'zscaler'}}), scenario().contextKey('a', {channels:{web:'alternative'}})));
test('CONTEXT-07-undeclared-and-explicit-scope-are-distinct', () => assert.notEqual(scenario().contextKey('a', {from_page:false}), scenario().contextKey('a', {from_page:true})));
test('CONTEXT-08-delimiter-like-tenant-ids-cannot-collide', () => assert.notEqual(scenario().contextKey('a,b', {scopes:['c']}), scenario().contextKey('a', {scopes:['b,c']})));
test('CONTEXT-09-context-canonicalization-is-nonmutating', () => { const s = {scopes:['zcc','dlp'], channels:{web:{choice:'zscaler'}}}, before=clone(s); scenario().contextKey('a',s); assert.deepEqual(s,before); });

test('JOIN-01-complete-identical-provenance-can-join', () => assert.equal(scenario().compatibleEvidence(evidence(), evidence()), true));
test('JOIN-02-same-engine-name-across-tenants-cannot-join', () => assert.equal(scenario().compatibleEvidence(evidence({name:'Engine A'}), evidence({name:'Engine A',tenant_key:'tenant-b'})), false));
test('JOIN-03-different-scope-cannot-join', () => assert.equal(scenario().compatibleEvidence(evidence(), evidence({scope_key:'scope-b'})), false));
test('JOIN-04-different-content-scenario-cannot-join', () => assert.equal(scenario().compatibleEvidence(evidence(), evidence({scenario_id:'new-content'})), false));
test('JOIN-05-stale-configuration-cannot-join', () => assert.equal(scenario().compatibleEvidence(evidence(), evidence({configuration_id:'older-read'})), false));
test('JOIN-06-missing-tenant-provenance-cannot-join', () => assert.equal(scenario().compatibleEvidence(evidence({tenant_key:''}), evidence({tenant_key:''})), false));
test('JOIN-07-missing-scope-provenance-cannot-join', () => assert.equal(scenario().compatibleEvidence(evidence({scope_key:''}), evidence({scope_key:''})), false));
test('JOIN-08-missing-scenario-provenance-cannot-join', () => assert.equal(scenario().compatibleEvidence(evidence({scenario_id:''}), evidence({scenario_id:''})), false));
test('JOIN-09-missing-configuration-provenance-cannot-join', () => assert.equal(scenario().compatibleEvidence(evidence({configuration_id:''}), evidence({configuration_id:''})), false));
test('JOIN-10-whitespace-only-provenance-is-not-a-proof', () => assert.equal(scenario().compatibleEvidence(evidence({tenant_key:' '}), evidence({tenant_key:' '})), false));
test('JOIN-11-null-evidence-is-not-a-match', () => assert.equal(scenario().compatibleEvidence(null, evidence()), false));
test('JOIN-12-identifiers-must-match-without-coercion', () => assert.equal(scenario().compatibleEvidence(evidence({scenario_id:1}), evidence({scenario_id:'1'})), false));

// Event display is explicitly tri-state and allowlisted. Lack of evidence
// must not be displayed as a measured zero, a known channel, or a live action.
test('EVENT-01-source-must-be-explicit', () => assert.throws(() => scenario().normalizeEvent(incident())));
test('EVENT-02-arbitrary-source-is-rejected', () => assert.throws(() => scenario().normalizeEvent(incident(), 'configuration')));
test('EVENT-03-observed-source-is-preserved', () => assert.equal(scenario().normalizeEvent(incident(), 'observed').provenance, 'observed'));
test('EVENT-04-demo-source-cannot-become-observed', () => assert.equal(scenario().normalizeEvent(incident(), 'demo').provenance, 'demo'));
test('EVENT-05-simulated-source-cannot-become-observed', () => assert.equal(scenario().normalizeEvent(incident(), 'simulated').provenance, 'simulated'));
test('EVENT-06-unrecognized-channel-is-unknown-not-web', () => assert.equal(scenario().normalizeEvent(incident({channel:'private-app'}), 'observed').channel, 'unknown'));
test('EVENT-07-missing-action-is-unknown-not-monitor', () => assert.equal(scenario().normalizeEvent(incident({enforcement:undefined}), 'observed').enforcement, 'unknown'));
test('EVENT-08-monitor-action-is-preserved', () => assert.equal(scenario().normalizeEvent(incident({enforcement:'monitor'}), 'observed').enforcement, 'monitor'));
test('EVENT-09-invalid-action-is-not-enforced', () => assert.equal(scenario().normalizeEvent(incident({enforcement:'blocked-maybe'}), 'observed').enforcement, 'unknown'));
test('EVENT-10-zero-dictionary-count-is-measured-zero', () => assert.equal(scenario().normalizeEvent(incident({dictionaries:[{name:'D',count:0}]}), 'observed').dictionaries[0].count, 0));
test('EVENT-11-missing-count-is-unknown', () => assert.equal(scenario().normalizeEvent(incident({dictionaries:[{name:'D'}]}), 'observed').dictionaries[0].count, null));
test('EVENT-12-numeric-string-is-not-trusted-as-measured-count', () => assert.equal(scenario().normalizeEvent(incident({dictionaries:[{name:'D',count:'3'}]}), 'observed').dictionaries[0].count, null));
test('EVENT-13-negative-count-is-unknown', () => assert.equal(scenario().normalizeEvent(incident({dictionaries:[{name:'D',count:-1}]}), 'observed').dictionaries[0].count, null));
test('EVENT-14-nonfinite-count-is-unknown', () => assert.equal(scenario().normalizeEvent(incident({dictionaries:[{name:'D',count:Infinity}]}), 'observed').dictionaries[0].count, null));
test('EVENT-15-user-and-file-identifiers-are-removed', () => { const e=scenario().normalizeEvent(incident({user:'private-user@example.test', user_name:'Private Person', file:'private-records.xlsx',password:'credential-value'}),'observed'); assert(!JSON.stringify(e).match(/private-user|Private Person|private-records|credential-value/)); });
test('EVENT-16-rule-inference-is-not-event-time-proof', () => assert.match(scenario().normalizeEvent(incident(),'observed').action_source, /unverified/));
test('EVENT-17-explicit-action-source-is-retained', () => assert.equal(scenario().normalizeEvent(incident({action_source:'event.action'}),'observed').action_source,'event.action'));
test('EVENT-18-malformed-rule-list-does-not-crash', () => { const e=scenario().normalizeEvent(incident({rules:'Rule A',engines:{name:'Engine A'}}),'observed'); assert.deepEqual(e.rules,[]); assert.deepEqual(e.engines,[]); });
test('EVENT-19-source-event-is-not-mutated', () => { const i=incident(), before=clone(i); scenario().normalizeEvent(i,'observed'); assert.deepEqual(i,before); });
test('EVENT-20-numeric-zero-event-id-is-preserved', () => assert.equal(scenario().normalizeEvent(incident({id:0}),'observed').id,'0'));

function ledger() {const l=scenario().createLedger(); l.reset('tenant-a'); return l;}
test('LEDGER-01-first-observed-event-is-counted', () => {const l=ledger(); assert(l.add(incident(),'observed','tenant-a')); assert.equal(l.counts('observed').seen,1);});
test('LEDGER-02-duplicate-observed-id-is-counted-once', () => {const l=ledger(); l.add(incident(),'observed','tenant-a'); assert.equal(l.add(incident(),'observed','tenant-a'),false); assert.equal(l.counts('observed').seen,1);});
test('LEDGER-03-changed-payload-does-not-duplicate-event-id', () => {const l=ledger(); l.add(incident(),'observed','tenant-a'); l.add(incident({enforcement:'monitor'}),'observed','tenant-a'); assert.equal(l.counts('observed').enforced,1); assert.equal(l.counts('observed').monitor,0);});
test('LEDGER-04-demo-never-increases-observed-count', () => {const l=ledger(); l.add(incident(),'demo','tenant-a'); assert.equal(l.counts('observed').seen,0); assert.equal(l.counts('demo').seen,1);});
test('LEDGER-05-simulation-never-increases-observed-count', () => {const l=ledger(); l.add(incident(),'simulated','tenant-a'); assert.equal(l.counts('observed').seen,0); assert.equal(l.counts('simulated').seen,1);});
test('LEDGER-06-same-id-in-distinct-provenance-is-not-deduped', () => {const l=ledger(); ['observed','simulated','demo'].forEach(m=>l.add(incident(),m,'tenant-a')); assert.equal(l.rows().length,3);});
test('LEDGER-07-stale-context-event-is-rejected', () => {const l=ledger(); assert.equal(l.add(incident(),'observed','tenant-b'),false); assert.equal(l.rows().length,0);});
test('LEDGER-08-reset-removes-prior-tenant-rows', () => {const l=ledger(); l.add(incident(),'observed','tenant-a'); l.reset('tenant-b'); assert.deepEqual(l.rows(),[]); assert.equal(l.context(),'tenant-b');});
test('LEDGER-09-reset-clears-event-deduplication', () => {const l=ledger(); l.add(incident(),'observed','tenant-a'); l.reset('tenant-b'); assert(l.add(incident(),'observed','tenant-b'));});
test('LEDGER-10-event-without-id-is-not-counted', () => {const l=ledger(); assert.equal(l.add(incident({id:''}),'observed','tenant-a'),false); assert.equal(l.counts('observed').seen,0);});
test('LEDGER-11-unknown-channel-has-its-own-count', () => {const l=ledger(); l.add(incident({channel:'private-app'}),'observed','tenant-a'); assert.equal(l.counts('observed').unknown_channel,1); assert.equal(l.counts('observed').web,0);});
test('LEDGER-12-unknown-action-has-its-own-count', () => {const l=ledger(); l.add(incident({enforcement:''}),'observed','tenant-a'); assert.equal(l.counts('observed').unknown,1); assert.equal(l.counts('observed').enforced,0);});
test('LEDGER-13-newest-events-appear-first', () => {const l=ledger(); l.add(incident({id:'older'}),'observed','tenant-a'); l.add(incident({id:'newer'}),'observed','tenant-a'); assert.deepEqual(l.rows().map(e=>e.id),['newer','older']);});
test('LEDGER-14-channel-totals-are-independent', () => {const l=ledger(); ['web','endpoint','email','saas'].forEach(ch=>l.add(incident({id:ch,channel:ch}),'observed','tenant-a')); const c=l.counts('observed'); assert.equal(c.seen,4); assert.deepEqual([c.web,c.endpoint,c.email,c.saas],[1,1,1,1]);});
test('LEDGER-15-history-is-bounded-and-evicted-ids-stay-deduped', () => {const l=ledger(); for(let i=0;i<501;i++)l.add(incident({id:String(i)}),'observed','tenant-a'); assert.equal(l.rows().length,500); assert.equal(l.rows().at(-1).id,'1'); assert.equal(l.add(incident({id:'0'}),'observed','tenant-a'),false);});
test('LEDGER-16-returned-top-level-rows-cannot-corrupt-ledger', () => {const l=ledger(); l.add(incident(),'observed','tenant-a'); l.rows()[0].enforcement='monitor'; assert.equal(l.counts('observed').enforced,1);});

// Generation tokens prevent late results from an older request taking over
// a newer session even when the selection is changed and changed back.
test('SESSION-01-new-session-is-not-running', () => assert.equal(scenario().createSession().running(),false));
test('SESSION-02-start-token-is-current-for-its-context', () => {const s=scenario().createSession(),t=s.start('a'); assert(s.running()); assert(s.current(t,'a'));});
test('SESSION-03-start-token-is-not-current-for-another-context', () => {const s=scenario().createSession(),t=s.start('a'); assert.equal(s.current(t,'b'),false);});
test('SESSION-04-stop-invalidates-inflight-token', () => {const s=scenario().createSession(),t=s.start('a'); s.stop(); assert.equal(s.current(t,'a'),false); assert.equal(s.running(),false);});
test('SESSION-05-restart-invalidates-earlier-same-context-token', () => {const s=scenario().createSession(),old=s.start('a'),fresh=s.start('a'); assert.equal(s.current(old,'a'),false); assert(s.current(fresh,'a'));});
test('SESSION-06-stop-then-start-cannot-resurrect-pending-result', () => {const s=scenario().createSession(),old=s.start('a'); s.stop(); const fresh=s.start('a'); assert.equal(s.current(old,'a'),false); assert(s.current(fresh,'a'));});
test('SESSION-07-context-roundtrip-does-not-resurrect-old-token', () => {const s=scenario().createSession(),old=s.start('a'); s.start('b'); s.start('a'); assert.equal(s.current(old,'a'),false);});
test('SESSION-08-missing-token-is-never-current', () => {const s=scenario().createSession();s.start('a');assert.equal(s.current(null,'a'),false);});
test('SESSION-09-token-generation-alone-does-not-authorize-context', () => {const s=scenario().createSession(),t=s.start('a');assert.equal(s.current({generation:t.generation,key:'b'},'a'),false);});

// Missing evidence uses warning/idle states; successful content simulation
// never becomes a claim of verified live enforcement.
test('RESPONSE-01-stage-object-reference-is-visible', () => {const m=scenario().responseModel(response()); assert.equal(m.hops[0].by,'Allowed destinations'); assert.match(m.hops[0].note,/url-7/); assert.match(m.hops[0].note,/configuration/);});
test('RESPONSE-02-limitations-survive-model-conversion', () => assert.deepEqual(scenario().responseModel(response()).limitations,['Event-time enforcement is not verified.']));
test('RESPONSE-03-scenario-identity-survives-model-conversion', () => {const m=scenario().responseModel(response()); assert.equal(m.scenario.tenant_key,'tenant-a'); assert.equal(m.scenario.configuration_id,'configuration-a'); assert.equal(m.scenario.operation,'upload');});
test('RESPONSE-04-corpus-result-survives-model-conversion', () => {const corpus={engines:[],results:[],predefined:[]}; assert.deepEqual(scenario().responseModel(response({corpus})).corpus,corpus);});
test('RESPONSE-05-missing-corpus-is-unmeasured', () => assert.equal(scenario().responseModel(response()).corpus,null));
test('RESPONSE-06-simulation-verdict-never-claims-enforcement', () => {const m=scenario().responseModel(response());assert.equal(m.verdict.outcome,'conditional');assert.equal(m.verdict.tone,'warn');assert.match(m.verdict.text,/not verified/);});
test('RESPONSE-07-web-missing-prerequisites-are-explicit', () => {const m=scenario().responseModel(response({stages:[{key:'dlp',status:'conditional'}]}));['url','ssl','ftc'].forEach(k=>{const h=m.hops.find(h=>h.key===k);assert(h);assert.equal(h.status,'unverified');assert.match(h.note,/not returned/);});});
test('RESPONSE-08-endpoint-does-not-inherit-inline-controls', () => {const r=response();r.scenario.channel='endpoint';r.stages=[{key:'endpoint',status:'conditional'}];const m=scenario().responseModel(r);['url','ssl','ftc'].forEach(k=>assert.equal(m.hops.find(h=>h.key===k).status,'not_applicable'));});
test('RESPONSE-09-email-does-not-inherit-inline-controls', () => {const r=response();r.scenario.channel='email';r.stages=[{key:'email',status:'conditional'}];const m=scenario().responseModel(r);assert.equal(m.hops.find(h=>h.key==='ssl').status,'not_applicable');});
test('RESPONSE-10-saas-does-not-inherit-inline-controls', () => {const r=response();r.scenario.channel='saas';r.stages=[{key:'saas',status:'conditional'}];const m=scenario().responseModel(r);assert.equal(m.hops.find(h=>h.key==='ftc').status,'not_applicable');});
test('RESPONSE-11-missing-stages-are-rejected', () => rejectResponse({scenario:response().scenario}));
test('RESPONSE-12-null-success-response-is-rejected', () => rejectResponse(null));
test('RESPONSE-13-unknown-channel-response-is-rejected', () => {const r=response();r.scenario.channel='private-app';rejectResponse(r);});
test('RESPONSE-14-unidentified-scenario-is-rejected', () => {const r=response();delete r.scenario.id;delete r.scenario.scenario_id;rejectResponse(r);});
test('RESPONSE-15-invalid-provenance-is-rejected', () => rejectResponse(response({provenance:'probably-live'})));
test('RESPONSE-16-null-stage-is-rejected', () => rejectResponse(response({stages:[null]})));
test('RESPONSE-17-unknown-stage-status-remains-warning', () => {const m=scenario().responseModel(response({stages:[{key:'custom',status:'future_status'}]}));assert.equal(m.hops[0].tone,'warn');});
test('RESPONSE-18-missing-stage-status-is-unverified', () => {const m=scenario().responseModel(response({stages:[{key:'dlp'}]}));assert.equal(m.hops[0].status,'unverified');assert.equal(m.hops[0].tone,'warn');});
test('RESPONSE-19-schema-version-mismatch-is-rejected', () => rejectResponse(response({schema_version:999})));
test('RESPONSE-20-empty-success-stages-are-not-a-complete-test', () => rejectResponse(response({stages:[]})));
test('RESPONSE-21-stage-without-identity-is-rejected', () => rejectResponse(response({stages:[{status:'pass'}]})));
test('RESPONSE-22-duplicate-stage-identities-are-rejected', () => rejectResponse(response({stages:[{key:'url',status:'blocked'},{key:'url',status:'pass'}]})));
test('RESPONSE-23-missing-web-control-is-warning-not-benign-idle', () => {const m=scenario().responseModel(response({stages:[{key:'dlp',status:'conditional'}]}));assert.equal(m.hops.find(h=>h.key==='ssl').tone,'warn');});
test('RESPONSE-24-blocking-stage-terminates-downstream-animation', () => {const m=scenario().responseModel(response({stages:[{key:'url',status:'blocked'},{key:'ssl',status:'not_reached'},{key:'ftc',status:'not_reached'}]}));assert.equal(m.stop,0);assert.equal(m.hops[1].tone,'after');});
test('RESPONSE-25-model-conversion-does-not-mutate-response', () => {const r=response(),before=clone(r);scenario().responseModel(r);assert.deepEqual(r,before);});

// These exercise semantically different tri-state renderer situations rather
// than treating every unknown as either green success or red enforcement.
test('TONE-01-enforced-block-is-a-stop', () => assert.equal(scenario().statusTone('blocked'),'stop'));
test('TONE-02-forwarding-bypass-is-a-stop', () => assert.equal(scenario().statusTone('bypass'),'stop'));
test('TONE-03-observed-stage-is-positive-evidence', () => assert.equal(scenario().statusTone('observed'),'pass'));
test('TONE-04-conditionally-matching-config-is-warning', () => assert.equal(scenario().statusTone('conditional'),'warn'));
test('TONE-05-out-of-scope-does-not-look-failed', () => assert.equal(scenario().statusTone('out_of_scope'),'idle'));
test('TONE-06-not-applicable-control-does-not-look-passed', () => assert.equal(scenario().statusTone('not_applicable'),'idle'));
test('TONE-07-missing-status-never-looks-passed', () => assert.equal(scenario().statusTone(undefined),'warn'));


// Destination validation needs to reject active content and credential-bearing
// URLs before the request can enter a service's configuration evaluator.
test('VALIDATE-24-javascript-url-is-rejected', () => badInput({destination:'javascript:alert(1)'}, 'destination'));
test('VALIDATE-25-file-url-is-rejected', () => badInput({destination:'file:///etc/passwd'}, 'destination'));
test('VALIDATE-26-credential-bearing-url-is-rejected', () => badInput({destination:'https://user:secret@example.test/'}, 'destination'));
test('VALIDATE-27-malformed-url-host-is-rejected', () => badInput({destination:'https:///not-a-host'}, 'destination'));
test('VALIDATE-28-hostname-with-port-is-valid', () => goodInput({destination:'example.test:8443'}));
test('VALIDATE-29-https-destination-with-query-is-valid', () => goodInput({destination:'https://example.test/upload?mode=test'}));

const ENDPOINT='/api/flow/scenario';
const liveResponse = (incs, patch) => Object.assign({incidents:incs || [],next_since:'next-cursor',stats:{},errors:[],read_at:'2026-10-05T12:00:00Z'},patch || {});
async function page(options) { const b=browser(options);await tick();return b; }
function fill(b, patch) {
  const fields=Object.assign({Channel:'web',Destination:'example.test',Operation:'upload',FileType:'txt',Network:'off',Platform:'windows',Corpus:'SYNTHETIC CONTENT'},patch || {});
  Object.entries(fields).forEach(([id,value])=>{b.get('scenario'+id).value=value;});
}
async function showResult(b, patch) {fill(b);b.queue(ENDPOINT,response(patch));await b.click('scenarioRun');}
const displayed=b=>b.newest('hopPlayer','scenarioHost');

test('PAGE-01-open-page-does-not-read-tenant-flow-or-live-data', async()=>{const b=await page();assert.deepEqual(b.requests.map(r=>r.url),['/api/tenant-profiles']);});
test('PAGE-02-test-without-content-stays-local', async()=>{const b=await page();fill(b,{Corpus:''});await b.click('scenarioRun');assert.equal(b.requests.filter(r=>r.url===ENDPOINT).length,0);assert.match(b.get('scenarioStatus').textContent,/content/i);});
test('PAGE-03-web-test-without-destination-stays-local', async()=>{const b=await page();fill(b,{Destination:''});await b.click('scenarioRun');assert.equal(b.requests.filter(r=>r.url===ENDPOINT).length,0);assert.match(b.get('scenarioStatus').textContent,/destination/i);});
test('PAGE-04-request-includes-one-complete-scenario', async()=>{const b=await page();await showResult(b);const r=b.requests.find(r=>r.url===ENDPOINT);assert.equal(r.init.method,'POST');assert.equal(r.body.channel,'web');assert.equal(r.body.destination,'example.test');assert.equal(r.body.operation,'upload');assert.equal(r.body.file_type,'txt');assert.equal(r.body.corpus,'SYNTHETIC CONTENT');assert.equal(r.body.network,'off');assert.equal(r.body.platform,'windows');});
test('PAGE-05-tenant-profile-id-is-bound-to-request', async()=>{const b=await page({profiles:[{id:'tenant-b',name:'Tenant B'}]});await b.change('faTenant','profile:tenant-b');await showResult(b);assert.equal(b.requests.find(r=>r.url===ENDPOINT).body.profile_id,'tenant-b');});
test('PAGE-06-current-scope-is-bound-to-request', async()=>{const b=await page({storage:{zassess_scopes_live_v1:JSON.stringify({scopes:['dlp','zcc']}),zassess_channels_v1:JSON.stringify({web:{choice:'zscaler'},email:{choice:'alternative'}})}});await showResult(b);const body=b.requests.find(r=>r.url===ENDPOINT).body;assert.deepEqual(body.scopes,['dlp','zcc']);assert.deepEqual(body.channels,{web:'zscaler',email:'alternative'});assert.equal(body.from_page,true);});
test('PAGE-07-valid-result-enables-guided-playback', async()=>{const b=await page();await showResult(b);['scenarioPlay','scenarioNext','scenarioRestart'].forEach(id=>assert.equal(b.get(id).disabled,false));assert(displayed(b));assert.match(b.get('scenarioStatus').textContent,/SIMULATED/);});
test('PAGE-08-invalid-json-shape-never-enables-playback', async()=>{const b=await page();fill(b);b.queue(ENDPOINT,{});await b.click('scenarioRun');assert.equal(b.get('scenarioPlay').disabled,true);assert(!displayed(b));assert.match(b.get('scenarioStatus').textContent,/failed/i);});
test('PAGE-09-http-failure-restores-run-control', async()=>{const b=await page();fill(b);b.queue(ENDPOINT,{detail:'Permission denied'},403);await b.click('scenarioRun');assert.equal(b.get('scenarioRun').disabled,false);assert.equal(b.get('scenarioCancel').hidden,true);assert.match(b.get('scenarioStatus').textContent,/Permission denied/);});
test('PAGE-10-network-failure-clears-previous-result', async()=>{const b=await page();await showResult(b);const first=displayed(b);b.reject(ENDPOINT,'Network unavailable');await b.click('scenarioRun');assert.equal(first.destroyed,true);assert.equal(b.get('scenarioPlay').disabled,true);assert.match(b.get('scenarioStatus').textContent,/Network unavailable/);});
test('PAGE-11-inflight-test-has-cancel-and-abort-signal', async()=>{const b=await page();fill(b);b.defer(ENDPOINT);await b.click('scenarioRun');assert.equal(b.get('scenarioRun').disabled,true);assert.equal(b.get('scenarioCancel').hidden,false);assert.equal(b.requests.find(r=>r.url===ENDPOINT).init.signal.aborted,false);});
test('PAGE-12-cancel-aborts-and-rejects-late-response', async()=>{const b=await page();fill(b);const pending=b.defer(ENDPOINT);await b.click('scenarioRun');const req=b.requests.find(r=>r.url===ENDPOINT);await b.click('scenarioCancel');assert.equal(req.init.signal.aborted,true);pending.resolve(response());await tick();assert(!displayed(b));assert.equal(b.get('scenarioRun').disabled,false);assert.match(b.get('scenarioStatus').textContent,/cancel/i);});
test('PAGE-13-edited-content-invalidates-inflight-test', async()=>{const b=await page();fill(b);const pending=b.defer(ENDPOINT);await b.click('scenarioRun');b.get('scenarioCorpus').value='NEW SYNTHETIC CONTENT';await b.event('scenarioCorpus','input');pending.resolve(response());await tick();assert(!displayed(b));assert.equal(b.get('scenarioPlay').disabled,true);});
test('PAGE-14-newer-test-wins-out-of-order-results', async()=>{const b=await page();fill(b);const old=b.defer(ENDPOINT);await b.click('scenarioRun');await b.click('scenarioCancel');const fresh=response({summary:'Newer result'});b.queue(ENDPOINT,fresh);await b.click('scenarioRun');old.resolve(response({summary:'Stale result'}));await tick();assert.match(b.get('scenarioStatus').textContent,/Newer result/);assert(!b.get('scenarioStatus').textContent.includes('Stale'));});
test('PAGE-15-tenant-switch-invalidates-inflight-test', async()=>{const b=await page();fill(b);const pending=b.defer(ENDPOINT);await b.click('scenarioRun');await b.change('faTenant','profile:other');pending.resolve(response());await tick();assert(!displayed(b));assert.equal(b.get('scenarioPlay').disabled,true);});
test('PAGE-16-scope-change-invalidates-inflight-test', async()=>{const b=await page();fill(b);const pending=b.defer(ENDPOINT);await b.click('scenarioRun');await b.windowEvent('storage',{key:'zassess_scopes_live_v1'});pending.resolve(response());await tick();assert(!displayed(b));});
test('PAGE-17-response-from-wrong-channel-is-rejected', async()=>{const b=await page();const r=response();r.scenario.channel='email';await showResult(b,r);assert(!displayed(b));assert.match(b.get('scenarioStatus').textContent,/match/i);});
test('PAGE-18-response-from-wrong-destination-is-rejected', async()=>{const b=await page();const r=response();r.scenario.destination='other.test';await showResult(b,r);assert(!displayed(b));assert.match(b.get('scenarioStatus').textContent,/match/i);});
test('PAGE-19-endpoint-selects-usb-and-disables-web-network', async()=>{const b=await page();await b.change('scenarioChannel','endpoint');assert.equal(b.get('scenarioOperation').value,'usb');assert.equal(b.get('scenarioNetwork').disabled,true);});
test('PAGE-20-email-selects-send-operation', async()=>{const b=await page();await b.change('scenarioChannel','email');assert.equal(b.get('scenarioOperation').value,'send');assert.equal(b.get('scenarioNetwork').disabled,true);});
test('PAGE-21-saas-selects-scan-operation', async()=>{const b=await page();await b.change('scenarioChannel','saas');assert.equal(b.get('scenarioOperation').value,'scan');assert.equal(b.get('scenarioNetwork').disabled,true);});
test('PAGE-22-returning-to-web-restores-network-control', async()=>{const b=await page();await b.change('scenarioChannel','endpoint');await b.change('scenarioChannel','web');assert.equal(b.get('scenarioOperation').value,'upload');assert.equal(b.get('scenarioNetwork').disabled,false);});
test('PAGE-23-guided-next-advances-current-player-only', async()=>{const b=await page();await showResult(b);await b.click('scenarioNext');assert.equal(displayed(b).steps,1);assert.equal(displayed(b).plays,0);});
test('PAGE-24-play-and-restart-use-current-scenario', async()=>{const b=await page();await showResult(b);await b.click('scenarioPlay');await b.click('scenarioRestart');assert.equal(displayed(b).plays,1);assert.equal(displayed(b).resets,1);});
test('PAGE-25-scenario-does-not-persist-test-content', async()=>{const b=await page();await showResult(b);assert.deepEqual(b.storageWrites,[]);});
test('PAGE-26-legacy-path-cache-never-seeds-new-scenario', async()=>{const b=await page({hash:'#path',storage:{zassess_path_last:JSON.stringify({at:'2025-01-01',result:models().SAMPLE.path})}});assert(!displayed(b));assert.equal(b.get('scenarioPlay').disabled,true);assert(!b.get('scenarioStatus').textContent.includes('drive.google'));});
test('PAGE-27-response-markup-is-escaped-in-stage-details', async()=>{const b=await page();const r=response();r.stages[0].label='<img src=x onerror=alert(1)>';r.limitations=['<script>alert(1)</script>'];await showResult(b,r);assert.equal(b.get('scenarioDetails').querySelectorAll('img').length,0);assert.equal(b.get('scenarioDetails').querySelectorAll('script').length,0);assert(b.get('scenarioDetails').textContent.includes('<script>'));});
test('PAGE-28-scenario-test-does-not-start-live-polling', async()=>{const b=await page();await showResult(b);await b.advance(60000);assert.equal(b.polls().length,0);});

test('LIVE-01-start-produces-one-initial-read', async()=>{const b=await page();await b.click('liveStart');assert.equal(b.polls().length,1);assert.equal(b.get('liveStart').hidden,true);assert.equal(b.get('liveStop').hidden,false);});
test('LIVE-02-repeated-start-does-not-duplicate-poll-chain', async()=>{const b=await page();await b.click('liveStart');await b.click('liveStart');await b.advance(45000);assert.equal(b.polls().length,4);});
test('LIVE-03-stop-cancels-scheduled-read', async()=>{const b=await page();await b.click('liveStart');await b.click('liveStop');await b.advance(60000);assert.equal(b.polls().length,1);assert.equal(b.get('liveStart').hidden,false);});
test('LIVE-04-stop-during-poll-rejects-late-events', async()=>{const b=await page();const pending=b.defer('/api/live-feed');await b.click('liveStart');const req=b.polls()[0];await b.click('liveStop');assert.equal(req.init.signal.aborted,true);pending.resolve(liveResponse([incident()]));await tick();await b.advance(45000);assert.equal(b.get('liveFeed').children.length,0);assert.equal(b.polls().length,1);});
test('LIVE-05-stop-start-during-poll-keeps-one-chain', async()=>{const b=await page();const pending=b.defer('/api/live-feed');await b.click('liveStart');await b.click('liveStop');await b.click('liveStart');pending.resolve(liveResponse([incident({id:'stale'})]));await tick();const initial=b.polls().length;await b.advance(45000);assert.equal(b.polls().length-initial,3);assert.equal(b.get('liveFeed').children.length,0);});
test('LIVE-06-poll-replay-is-deduplicated', async()=>{const b=await page();b.queue('/api/live-feed',liveResponse([incident()]));b.queue('/api/live-feed',liveResponse([incident()]));await b.click('liveStart');await b.advance(15000);assert.equal(b.get('liveFeed').children.length,1);assert.match(b.get('liveVerdict').textContent,/1 unique/);});
test('LIVE-07-demo-does-not-change-live-rows-or-counts', async()=>{const b=await page();b.queue('/api/live-feed',liveResponse([incident()]));await b.click('liveStart');const before=b.get('liveVerdict').textContent;await b.click('liveSample');assert.equal(b.get('liveVerdict').textContent,before);assert.equal(b.get('liveFeed').children.length,1);assert.match(b.get('liveDemoStatus').textContent,/DEMO/);assert.equal(b.newest('live','liveDemoHost').pushed.length,4);});
test('LIVE-08-demo-does-not-start-live-reads', async()=>{const b=await page();await b.click('liveSample');await b.advance(30000);assert.equal(b.polls().length,0);assert.equal(b.get('liveFeed').children.length,0);});
test('LIVE-09-tenant-change-resets-feed-cursor-and-counts', async()=>{const b=await page();b.queue('/api/live-feed',liveResponse([incident()],{next_since:'tenant-a-cursor'}));await b.click('liveStart');await b.change('faTenant','profile:b');assert.equal(b.get('liveFeed').children.length,0);assert.match(b.get('liveVerdict').textContent,/0 unique/);await b.click('liveStart');assert.equal(b.polls().at(-1).body.since,'');assert.deepEqual(b.polls().at(-1).body.stats,{});});
test('LIVE-10-tenant-change-rejects-inflight-old-tenant-events', async()=>{const b=await page();const pending=b.defer('/api/live-feed');await b.click('liveStart');await b.change('faTenant','profile:b');pending.resolve(liveResponse([incident()]));await tick();assert.equal(b.get('liveFeed').children.length,0);});
test('LIVE-11-scope-change-stops-and-clears-feed', async()=>{const b=await page();b.queue('/api/live-feed',liveResponse([incident()]));await b.click('liveStart');await b.windowEvent('storage',{key:'zassess_channels_v1'});await b.advance(45000);assert.equal(b.get('liveFeed').children.length,0);assert.equal(b.polls().length,1);});
test('LIVE-12-malformed-success-keeps-last-good-cursor', async()=>{const b=await page();b.queue('/api/live-feed',liveResponse([],{next_since:'good'}));b.queue('/api/live-feed',{incidents:{},next_since:'bad'});await b.click('liveStart');await b.advance(30000);assert.equal(b.polls()[2].body.since,'good');});
test('LIVE-13-partial-error-does-not-advance-cursor-or-render-events', async()=>{const b=await page();b.queue('/api/live-feed',liveResponse([],{next_since:'good'}));b.queue('/api/live-feed',liveResponse([incident()],{next_since:'partial',errors:['Permission denied']}));await b.click('liveStart');await b.advance(30000);assert.equal(b.polls()[2].body.since,'good');assert.equal(b.get('liveFeed').children.length,0);});
test('LIVE-14-bad-request-stops-retry-loop', async()=>{const b=await page();b.queue('/api/live-feed',{detail:'Choose a tenant'},400);await b.click('liveStart');await b.advance(60000);assert.equal(b.polls().length,1);assert.match(b.get('liveVerdict').textContent,/Choose a tenant/);});
test('LIVE-15-transient-network-error-is-retryable', async()=>{const b=await page();b.reject('/api/live-feed','Temporary failure');await b.click('liveStart');assert.match(b.get('liveVerdict').textContent,/Temporary failure/);await b.advance(15000);assert.equal(b.polls().length,2);});
test('LIVE-16-unload-aborts-request-and-cancels-future-polls', async()=>{const b=await page();b.defer('/api/live-feed');await b.click('liveStart');await b.windowEvent('beforeunload');assert.equal(b.polls()[0].init.signal.aborted,true);await b.advance(60000);assert.equal(b.polls().length,1);});
test('LIVE-17-malicious-rule-name-is-rendered-as-text', async()=>{const b=await page();b.queue('/api/live-feed',liveResponse([incident({rules:['<img src=x onerror=alert(1)>']})]));await b.click('liveStart');assert.equal(b.get('liveFeed').querySelectorAll('img').length,0);assert(b.get('liveFeed').textContent.includes('<img'));});
test('LIVE-18-live-result-does-not-write-browser-storage', async()=>{const b=await page();b.queue('/api/live-feed',liveResponse([incident()]));await b.click('liveStart');await b.click('liveSample');assert.deepEqual(b.storageWrites,[]);});
test('LIVE-19-unknown-channel-stays-unknown-in-animation', async()=>{const b=await page();b.queue('/api/live-feed',liveResponse([incident({channel:'private-app'})]));await b.click('liveStart');assert.equal(b.newest('live','liveHost').pushed[0].channel,'unknown');assert.match(b.get('liveVerdict').textContent,/unknown channel 1/);});
test('LIVE-20-missing-dictionary-count-stays-unknown-in-animation', async()=>{const b=await page();b.queue('/api/live-feed',liveResponse([incident({dictionaries:[{name:'D'}]})]));await b.click('liveStart');assert.equal(b.newest('live','liveHost').pushed[0].dicts[0].count,null);});


// Downstream content/rule models must preserve uncertainty and use channel +
// object identity, never a coincidentally matching display name, for actions.
function corpus(patch) {
  return Object.assign({results:[{id:1,name:'Synthetic dictionary',total_hits:3}],predefined:[],engines:[{id:7,name:'Shared engine',expression:'D1.S > 1',fires:true,terms:['D1.S > 1: 3 → true'],rules:['Shared rule'],rule_objects:[{id:42,channel:'web',name:'Shared rule'}]}]},patch||{});
}
test('CORPUS-01-name-only-rule-reference-does-not-borrow-action',()=>{const c=corpus();delete c.engines[0].rule_objects;const m=models().corpusModel(c,{rules:[{name:'Shared rule',action:'BLOCK'}]});assert.equal(m.rules[0].action,null);});
test('CORPUS-02-same-id-on-different-channel-does-not-borrow-action',()=>{const m=models().corpusModel(corpus(),{rules:[{id:42,channel:'email',name:'Shared rule',action:'BLOCK'}]});assert.equal(m.rules[0].action,null);});
test('CORPUS-03-matching-channel-and-id-uses-configured-action',()=>{const m=models().corpusModel(corpus(),{rules:[{id:42,channel:'web',name:'Current name',action:'BLOCK'}]});assert.equal(m.rules[0].action,'BLOCK');assert.equal(m.rules[0].channel,'web');});
test('CORPUS-04-distinct-rule-ids-with-same-name-stay-separate',()=>{const c=corpus();c.engines[0].rule_objects.push({id:43,channel:'web',name:'Shared rule',action:'ALLOW'});const m=models().corpusModel(c);assert.equal(m.rules.length,2);assert.deepEqual(m.rules.map(r=>r.id),['42','43']);});
test('CORPUS-05-disabled-rule-is-not-an-active-candidate',()=>{const m=models().corpusModel(corpus(),{rules:[{id:42,channel:'web',action:'BLOCK',state:'DISABLED'}]});assert(!models().drillSummary(m).includes('Rule candidates:'));});
test('CORPUS-06-enabled-rule-remains-a-candidate-not-enforcement-proof',()=>{const m=models().corpusModel(corpus(),{rules:[{id:42,channel:'web',action:'BLOCK',state:'ENABLED'}]});assert.match(models().drillSummary(m),/not proven/);});
test('CORPUS-07-unread-dictionary-count-is-unknown-not-zero',()=>{const c=corpus();delete c.results[0].total_hits;assert.equal(models().corpusModel(c).dicts[0].count,null);});
test('CORPUS-08-explicitly-unsimulated-dictionary-count-is-unknown',()=>{const c=corpus();c.results[0].simulated=false;assert.equal(models().corpusModel(c).dicts[0].count,null);});
test('CORPUS-09-unknown-engine-never-becomes-no-match',()=>{const c=corpus();c.engines[0].fires=null;c.engines[0].terms=['D1.S > 1: unknown (not simulated)'];const m=models().corpusModel(c);assert.equal(m.engines[0].why.kind,'unknown');assert.match(models().drillSummary(m),/absence of a match is not established/);});
test('CORPUS-10-read-error-prevents-no-match-conclusion',()=>{const c=corpus({errors:['Dictionary list unreadable']});c.engines[0].fires=false;const m=models().corpusModel(c);assert.equal(m.incomplete,true);assert.match(models().drillSummary(m),/incomplete/);assert(!models().drillSummary(m).includes('No engine matches'));});
test('CORPUS-11-unverified-read-evidence-prevents-no-match-conclusion',()=>{const c=corpus({read_evidence:{dictionaries:{status:'unverified'}}});c.engines[0].fires=false;assert.match(models().drillSummary(models().corpusModel(c)),/incomplete/);});
test('CORPUS-12-folded-engine-total-counts-hidden-results',()=>{const c=corpus();c.engines=Array.from({length:8},(_,i)=>({id:i,name:'Engine '+i,fires:true,terms:[],rules:[]}));const m=models().corpusModel(c);assert.equal(m.engines.length,6);assert.equal(m.hidden.engines,2);assert.match(models().drillSummary(m),/8 engine\(s\)/);});
test('CORPUS-13-composite-expression-is-not-explained-by-one-term',()=>{const c=corpus();Object.assign(c.engines[0],{expression:'D1.S > 4 and D2.S > 2',fires:false,terms:['D1.S > 4: 3 → false','D2.S > 2: 0 → false']});const m=models().corpusModel(c);assert.notEqual(m.engines[0].why.kind,'near');assert(!m.engines[0].why.text.includes('needs more than 4'));});
test('CORPUS-14-server-explanation-is-preserved',()=>{const c=corpus();c.engines[0].explanation='Any branch failed because the exclusion matched.';assert.equal(models().corpusModel(c).engines[0].why.text,c.engines[0].explanation);});
test('CORPUS-15-unmeasured-path-summary-does-not-claim-content-match',()=>{assert.match(models().drillSummary({measured:false}),/unverified/);});

test('PAGE-29-dictionary-unknown-and-measured-zero-are-distinct',async()=>{const b=await page();const r=response();r.stages.push({key:'dictionary',status:'simulated',objects:[{id:1,name:'Unknown dictionary',count:null},{id:2,name:'Zero dictionary',count:0}]});await showResult(b,r);const text=b.get('scenarioDetails').textContent;assert.match(text,/Unknown dictionary · ID 1 · count unknown/);assert.match(text,/Zero dictionary · ID 2 · count 0/);});
test('PAGE-30-stage-engine-identity-expression-and-tristate-are-visible',async()=>{const b=await page();const r=response();r.stages.push({key:'engine',status:'simulated',objects:[{id:7,name:'Engine A',expression:'D1.S > 4',fires:null,engine_ids:[8,9]}]});await showResult(b,r);const text=b.get('scenarioDetails').textContent;assert.match(text,/Engine A · ID 7/);assert.match(text,/D1.S > 4 · match unknown/);assert.match(text,/engine IDs 8, 9/);});
test('PAGE-31-content-edit-clears-prior-detection-model',async()=>{const b=await page();await showResult(b,{corpus:corpus()});const prior=b.newest('drill','dlpHost');assert(prior);b.get('scenarioCorpus').value='New content';await b.event('scenarioCorpus','input');assert.equal(prior.destroyed,true);assert.equal(b.get('dlpReplay').disabled,true);assert.equal(b.get('dlpLog').textContent,'');});
test('PAGE-32-simulation-never-changes-observed-counts',async()=>{const b=await page();b.queue('/api/live-feed',liveResponse([incident()]));await b.click('liveStart');const before=b.get('liveVerdict').textContent;await showResult(b,{corpus:corpus()});assert.equal(b.get('liveVerdict').textContent,before);assert.equal(b.get('liveFeed').children.length,1);});
test('PAGE-33-detection-demo-never-overwrites-scenario-graph',async()=>{const b=await page();await showResult(b,{corpus:corpus()});const before=displayed(b);await b.navigate('dlp');await b.click('dlpSample');assert.equal(displayed(b),before);assert.match(b.get('dlpSrc').textContent,/never joined/);assert.match(b.get('scenarioStatus').textContent,/SIMULATED/);});


function pathAndCorpus() {
  const c=models().corpusModel(corpus());c.context=evidence();
  const p={context:evidence(),dest:'example.test',dlp:{rules:[{name:'Rule A',action:'BLOCK',engines:['Shared engine'],engine_ids:[7]}]}};
  return {p,c};
}
test('PATHJOIN-01-legacy-name-only-caches-remain-unmeasured',()=>{const fa=models(),m=fa.pathDrillModel(fa.pathModel(fa.SAMPLE.path),fa.corpusModel(fa.SAMPLE.corpus));assert.equal(m.measured,false);assert(m.engines.every(e=>e.why.kind==='unmeasured'));});
test('PATHJOIN-02-complete-context-and-id-can-join-counts',()=>{const {p,c}=pathAndCorpus();const m=models().pathDrillModel(p,c);assert.equal(m.measured,true);assert.equal(m.engines[0].id,7);assert.equal(m.dicts[0].count,3);});
test('PATHJOIN-03-stale-tenant-corpus-cannot-join-by-engine-id',()=>{const {p,c}=pathAndCorpus();c.context.tenant_key='other';const m=models().pathDrillModel(p,c);assert.equal(m.measured,false);assert.equal(m.dicts.length,0);});
test('PATHJOIN-04-matching-context-without-engine-id-is-unmeasured',()=>{const {p,c}=pathAndCorpus();delete p.dlp.rules[0].engine_ids;assert.equal(models().pathDrillModel(p,c).measured,false);});
test('PATHJOIN-05-same-name-different-engine-ids-stay-separate',()=>{const {p,c}=pathAndCorpus();p.dlp.rules[0].engines.push('Shared engine');p.dlp.rules[0].engine_ids.push(8);c.engines.push(Object.assign({},c.engines[0],{id:8,fires:false,why:{kind:'none',text:'No match'}}));const m=models().pathDrillModel(p,c);assert.equal(m.engines.length,2);assert.deepEqual(m.engines.map(e=>e.id),[7,8]);});
test('CONFIG-01-configuration-validation-allows-empty-corpus',()=>assert.deepEqual(scenario().validateInput(input({corpus:''}),{requireCorpus:false}),[]));
test('CONFIG-02-configuration-validation-still-needs-web-destination',()=>assert(scenario().validateInput(input({corpus:'',destination:''}),{requireCorpus:false}).some(e=>/destination/i.test(e))));
test('CONFIG-03-mode-without-top-level-provenance-is-labelled-configuration',()=>{const r=response();delete r.provenance;r.scenario.mode='configuration';assert.equal(scenario().responseModel(r).provenance,'configuration');});
test('CONFIG-04-configuration-button-runs-without-test-content',async()=>{const b=await page();fill(b,{Corpus:''});const r=response();delete r.provenance;r.scenario.mode='configuration';b.queue(ENDPOINT,r);await b.click('scenarioTrace');assert(displayed(b));assert.match(b.get('scenarioStatus').textContent,/CONFIGURATION/);assert.equal(b.requests.find(r=>r.url===ENDPOINT).body.corpus,'');});
test('CONFIG-05-configuration-button-does-not-transmit-text-left-in-form',async()=>{const b=await page();fill(b,{Corpus:'SYNTHETIC TEXT LEFT IN FORM'});const r=response();delete r.provenance;r.scenario.mode='configuration';b.queue(ENDPOINT,r);await b.click('scenarioTrace');assert.equal(b.requests.find(r=>r.url===ENDPOINT).body.corpus,'');assert.equal(b.get('scenarioCorpus').value,'SYNTHETIC TEXT LEFT IN FORM');});
test('CONFIG-06-inflight-configuration-disables-both-read-buttons',async()=>{const b=await page();fill(b,{Corpus:''});b.defer(ENDPOINT);await b.click('scenarioTrace');assert.equal(b.get('scenarioRun').disabled,true);assert.equal(b.get('scenarioTrace').disabled,true);await b.click('scenarioRun');assert.equal(b.requests.filter(r=>r.url===ENDPOINT).length,1);});
test('CONFIG-07-cancelling-configuration-restores-both-buttons',async()=>{const b=await page();fill(b,{Corpus:''});b.defer(ENDPOINT);await b.click('scenarioTrace');await b.click('scenarioCancel');assert.equal(b.get('scenarioRun').disabled,false);assert.equal(b.get('scenarioTrace').disabled,false);assert.equal(b.get('scenarioPlay').disabled,true);});
test('INPUT-11-legacy-activity-alias-is-preserved',()=>assert.equal(scenario().normalizeInput({activity:'download'}).operation,'download'));
test('RESPONSE-26-duplicate-normalized-stage-identities-are-rejected',()=>rejectResponse(response({stages:[{key:'url',status:'blocked'},{key:' url ',status:'pass'}]})));

test('PAGE-34-opener-tenant-change-without-selector-change-rejects-result', async()=>{let tenant='first';const b=await page({opener:{migrateCredBody:()=>({vanity_domain:tenant,client_id:'client'})}});fill(b);const pending=b.defer(ENDPOINT);await b.click('scenarioRun');tenant='second';pending.resolve(response());await tick();assert(!displayed(b));assert.equal(b.get('scenarioRun').disabled,false);assert.match(b.get('scenarioStatus').textContent,/discarded/);});
test('LIVE-21-opener-tenant-change-rejects-old-event-and-stops-session', async()=>{let tenant='first';const b=await page({opener:{migrateCredBody:()=>({vanity_domain:tenant,client_id:'client'})}});const pending=b.defer('/api/live-feed');await b.click('liveStart');tenant='second';pending.resolve(liveResponse([incident()]));await tick();await b.advance(45000);assert.equal(b.get('liveFeed').children.length,0);assert.equal(b.polls().length,1);assert.equal(b.get('liveStart').hidden,false);});

test('LIVECTRL-01-web-prerequisites-are-explicitly-unverified',()=>{const c=models().liveModel(incident()).controls;assert.deepEqual(c.map(x=>x.label),['URL Filtering','SSL Inspection','File Type Control']);assert(c.every(x=>x.status==='unverified'&&/not present/i.test(x.reason)));});
test('LIVECTRL-02-endpoint-controls-are-not-fake-inline-hops',()=>{const c=models().liveModel(incident({channel:'endpoint'})).controls;assert(c.every(x=>x.status==='not_applicable'));});
test('LIVECTRL-03-email-controls-retain-applicability-reason',()=>{const c=models().liveModel(incident({channel:'email'})).controls;assert(c.every(x=>x.status==='not_applicable'&&/not an enforcement hop/.test(x.reason)));});
test('LIVECTRL-04-saas-controls-stay-outside-at-rest-enforcement',()=>{const c=models().liveModel(incident({channel:'saas'})).controls;assert(c.every(x=>x.status==='not_applicable'));});
test('LIVECTRL-05-unknown-channel-does-not-assume-applicability',()=>{const c=models().liveModel(incident({channel:'missing-channel'})).controls;assert(c.every(x=>x.status==='unverified'));});

test('CONFIG-08-definition-graph-does-not-claim-synthetic-content',async()=>{const b=await page();fill(b,{Corpus:''});const r=response({corpus:corpus({mode:'configuration'})});delete r.provenance;r.scenario.mode='configuration';b.queue(ENDPOINT,r);await b.click('scenarioTrace');assert.match(b.get('dlpSrc').textContent,/CONFIGURATION.*no content tested/);assert(!b.get('dlpSrc').textContent.includes('SIMULATED'));const drill=b.newest('drill','dlpHost');assert.equal(drill.model.measured,false);assert.equal(drill.model.source.label,'Configuration references');assert.equal(drill.plays,0);assert.equal(b.get('dlpReplay').disabled,true);});

test('CORPUS-16-disabled-applicability-overrides-unknown-state',()=>{const m=models().corpusModel(corpus(),{rules:[{id:42,channel:'web',name:'DisabledFlag',action:'BLOCK',state:'UNKNOWN',applicability:'disabled'}]});assert(!models().drillSummary(m).includes('Rule candidates:'));});
test('LIVE-22-stop-destroys-pending-lane-playback',async()=>{const b=await page();b.queue('/api/live-feed',liveResponse([incident()]));await b.click('liveStart');const lane=b.newest('live','liveHost');await b.click('liveStop');assert.equal(lane.destroyed,true);assert.equal(b.get('liveFeed').children.length,1);await b.click('liveStart');assert.notEqual(b.newest('live','liveHost'),lane);});

// The Path analyzer's kept result replayed in the #path view: its own player,
// never the scenario's, escaped, with the hop-by-hop chain as the second picture.
const keptPath=()=>({zassess_path_last:JSON.stringify({at:'2026-01-01T00:00:00Z',result:models().SAMPLE.traffic})});
test('PATHREPLAY-01-kept-result-replays-with-step-controls',async()=>{const b=await page({hash:'#path',storage:keptPath()});const p=b.newest('trafficPath','tpHost');assert(p);assert.equal(p.opts.stepper,true);assert.equal(p.model.mode,'result');assert.equal(p.model.nodes[p.model.stop].key,'url');assert.match(b.get('tpSrc').textContent,/From the Path analyzer/);assert(!displayed(b));assert.equal(b.get('scenarioPlay').disabled,true);});
test('PATHREPLAY-02-no-result-shows-a-labelled-sample',async()=>{const b=await page({hash:'#path'});const p=b.newest('trafficPath','tpHost');assert(p);assert.match(b.get('tpSrc').textContent,/Sample/);assert.match(b.get('tpSrc').textContent,/sample data/);});
test('PATHREPLAY-03-hop-by-hop-is-the-second-picture',async()=>{const b=await page({hash:'#path',storage:keptPath()});const first=b.newest('trafficPath','tpHost');await b.change('tpView','hops');assert.equal(first.destroyed,true);assert(b.newest('hopPlayer','tpHopHost'));assert.equal(b.get('tpHopWrap').hidden,false);await b.change('tpView','path');assert(b.newest('trafficPath','tpHost')!==first);});
test('PATHREPLAY-04-tenant-strings-are-escaped',async()=>{const r=clone(models().SAMPLE.traffic);r.destination.host='<img src=x onerror=alert(1)>';r.whatif.identity_label='<script>alert(1)</script>';r.verdict.headline='<b>x</b>';const b=await page({hash:'#path',storage:{zassess_path_last:JSON.stringify({at:'2026-01-01',result:r})}});assert.equal(b.get('tpSrc').querySelectorAll('img').length,0);assert.equal(b.get('tpWhatif').querySelectorAll('script').length,0);assert(b.get('tpWhatif').textContent.includes('<script>'));assert(b.get('tpSrc').textContent.includes('<img'));});

async function main() {
  const choice = process.argv[2];
  if (choice === '--list') { process.stdout.write(JSON.stringify([...CASES.keys()])); return; }
  if (choice === '--all') {
    const reports=[];
    for (const [id, fn] of CASES) {
      try {await fn();reports.push({id,passed:true});}
      catch (error) {reports.push({id,passed:false,error:error.stack});}
    }
    process.stdout.write(JSON.stringify(reports,null,2));
    if (reports.some(r=>!r.passed)) process.exitCode=1;
    return;
  }
  assert(CASES.has(choice),'Unknown scenario case ID: '+choice);
  await CASES.get(choice)();
  process.stdout.write(JSON.stringify({id:choice,passed:true}));
}
main().catch(error=>{process.stderr.write(error.stack+'\n');process.exitCode=1;});
