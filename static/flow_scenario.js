/* Shared, offline scenario/evidence contract. No credentials, payload persistence or network calls. */
(function (root) {
  'use strict';
  const CHANNELS = ['web', 'endpoint', 'email', 'saas'];
  const MODES = ['observed', 'simulated', 'demo'];
  const CONTROLS = [['url', 'URL Filtering'], ['ssl', 'SSL Inspection'], ['ftc', 'File Type Control']];
  const str = x => x == null ? '' : String(x);
  const norm = x => str(x).trim();
  function normalizeInput(raw) {
    const r = raw || {};
    return { channel: norm(r.channel).toLowerCase() || 'web', destination: norm(r.destination),
      operation: norm(r.operation || r.activity) || 'upload', network: norm(r.network) || 'off', platform: norm(r.platform) || 'windows',
      file_type: norm(r.file_type).replace(/^\./, '').toLowerCase(), corpus: str(r.corpus), scenario_id: norm(r.scenario_id) };
  }
  function validateInput(raw, options) {
    const r = normalizeInput(raw), errors = [];
    if (CHANNELS.indexOf(r.channel) < 0) errors.push('Choose a supported test channel.');
    if (!r.corpus.trim() && !(options && options.requireCorpus === false)) errors.push('Add synthetic test content.');
    if (new TextEncoder().encode(r.corpus).length > 262144) errors.push('Test content must be at most 256 KiB.');
    if (r.channel === 'web' && !r.destination) errors.push('Enter the test destination.');
    if (r.channel === 'web' && r.destination) {
      if (/^https?:\/\//i.test(r.destination) && !/^https?:\/\/[^/?#]+/i.test(r.destination)) errors.push('Enter a valid destination with a hostname.');
      try {
        const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(r.destination) ? r.destination : 'https://' + r.destination);
        if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || /[:]/.test(r.destination.split('/')[0]) && !/^https?:\/\//i.test(r.destination) && !/^[^:]+:\d+(?:\/|$)/.test(r.destination)) errors.push('Use an HTTP(S) destination without embedded credentials.');
      } catch (e) { errors.push('Enter a valid destination hostname or HTTP(S) URL.'); }
    }
    if (r.destination.length > 2048) errors.push('Destination is too long.');
    if (r.destination && /[\x00-\x20<>]/.test(r.destination)) errors.push('Destination contains invalid characters.');
    if (r.file_type && !/^[a-z0-9][a-z0-9_.+-]{0,31}$/.test(r.file_type)) errors.push('Use a file type such as txt, pdf or xlsx.');
    if (['off', 'on', 'vpn'].indexOf(r.network) < 0) errors.push('Choose a supported network.');
    if (['windows', 'macos', 'ios', 'android', 'linux'].indexOf(r.platform) < 0) errors.push('Choose a supported platform.');
    if (!/^[a-z][a-z0-9_-]{0,63}$/.test(r.operation)) errors.push('Choose a supported operation.');
    return errors;
  }
  function stable(value) {
    if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']';
    if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + stable(value[k])).join(',') + '}';
    return JSON.stringify(value);
  }
  function contextKey(tenant, scope) {
    const s = scope || {}, c = {};
    Object.keys(s.channels || {}).sort().forEach(k => { const v = s.channels[k]; c[k] = v && typeof v === 'object' ? v.choice : v; });
    return stable({ tenant: norm(tenant), scopes: (s.scopes || []).map(String).sort(), channels: c, from_page: !!s.from_page });
  }
  function compatibleEvidence(a, b) {
    return !!a && !!b && ['tenant_key', 'scope_key', 'configuration_id'].every(k => norm(a[k]) && a[k] === b[k]) && !!norm(a.scenario_id || a.id) && (a.scenario_id || a.id) === (b.scenario_id || b.id);
  }
  function normalizeEvent(raw, mode) {
    if (MODES.indexOf(mode) < 0) throw new Error('Evidence source is required.');
    const r = raw || {}, channel = CHANNELS.indexOf(r.channel) >= 0 ? r.channel : 'unknown';
    return { id: norm(r.id), channel, provenance: mode, at: norm(r.created_at || r.at),
      rules: Array.isArray(r.rules) ? r.rules.map(str) : [], engines: Array.isArray(r.engines) ? r.engines.map(str) : [],
      dictionaries: (Array.isArray(r.dictionaries) ? r.dictionaries : []).map(d => ({ name: str(d.name), count: typeof d.count === 'number' && Number.isFinite(d.count) && d.count >= 0 ? d.count : null })),
      enforcement: ['enforced', 'monitor'].indexOf(r.enforcement) >= 0 ? r.enforcement : 'unknown',
      destination: str(r.host || r.destination || r.application), action_source: norm(r.action_source) || 'configured rule inference; event-time action unverified' };
  }
  function createLedger() {
    let context = '', seen = new Set(), rows = [];
    function reset(key) { context = str(key); seen = new Set(); rows = []; }
    function add(raw, mode, key) {
      if (str(key) !== context) return false;
      const e = normalizeEvent(raw, mode);
      // Missing IDs cannot establish event identity; keep them uncounted.
      if (!e.id) return false;
      const id = mode + ':' + e.id;
      if (seen.has(id)) return false;
      seen.add(id); rows.unshift(e); rows = rows.slice(0, 500);
      return e;
    }
    function counts(mode) {
      const r = rows.filter(e => e.provenance === mode), out = { seen: r.length, enforced: 0, monitor: 0, unknown: 0, web: 0, endpoint: 0, email: 0, saas: 0, unknown_channel: 0 };
      r.forEach(e => { out[e.enforcement]++; out[e.channel === 'unknown' ? 'unknown_channel' : e.channel]++; });
      return out;
    }
    return { reset, add, counts, rows: mode => rows.filter(e => !mode || e.provenance === mode).map(e => Object.assign({}, e)), context: () => context };
  }
  function createSession() {
    let generation = 0, running = false, key = '';
    return { start(k) { generation++; key = str(k); running = true; return { generation, key }; },
      stop() { generation++; running = false; }, current(token, k) { return running && !!token && token.generation === generation && token.key === key && key === str(k); },
      running: () => running };
  }
  const statusTone = status => ['blocked', 'bypass'].includes(status) ? 'stop' : ['pass', 'verified', 'observed'].includes(status) ? 'pass' : ['not_reached', 'not_applicable', 'out_of_scope', 'skipped'].includes(status) ? 'idle' : 'warn';
  function responseModel(raw) {
    if (!raw || typeof raw !== 'object' || raw.schema_version !== 1 || !Array.isArray(raw.stages) || !raw.stages.length || !raw.scenario || typeof raw.scenario !== 'object' || Array.isArray(raw.scenario)) throw new Error('The scenario response is incomplete. No result was accepted.');
    const scenario = raw.scenario;
    const keys = new Set();
    raw.stages.forEach(s => { if (!s || typeof s !== 'object' || Array.isArray(s) || !norm(s.key) || keys.has(norm(s.key))) throw new Error('The scenario contains invalid or duplicate stages.'); keys.add(norm(s.key)); });
    if (CHANNELS.indexOf(scenario.channel) < 0 || !norm(scenario.scenario_id || scenario.id)) throw new Error('The response does not identify the tested channel and scenario.');
    const hops = raw.stages.map(s => ({ key: norm(s.key), label: norm(s.label) || norm(s.key), status: norm(s.status) || 'unverified',
      tone: statusTone(s.status), sub: norm(s.object_name) || norm(s.status) || 'unverified',
      objects: (Array.isArray(s.objects) ? s.objects : []).filter(o => o && typeof o === 'object').map(o => ({ id: o.id, name: str(o.name), count: o.count, expression: o.expression, fires: o.fires, action: o.action, state: o.state, applicability: o.applicability, reason: o.reason, engine_ids: o.engine_ids, dictionary_refs: o.dictionary_refs })),
      by: norm(s.object_name), note: [norm(s.detail), s.object_id != null ? 'Object ID: ' + s.object_id : '', norm(s.evidence_status || s.provenance || s.source)].filter(Boolean).join(' · ') }));
    CONTROLS.forEach(([key, label]) => { if (!hops.some(h => h.key === key)) hops.push({ key, label, status: scenario.channel === 'web' ? 'unverified' : 'not_applicable', tone: scenario.channel === 'web' ? 'warn' : 'idle', sub: scenario.channel === 'web' ? 'unverified' : 'not applicable', by: '', note: scenario.channel === 'web' ? 'Required control was not returned.' : 'Inline web control; not part of the selected channel.' }); });
    const source = raw.provenance || (scenario.mode === 'configuration' ? 'configuration' : 'simulated');
    if (!MODES.concat(['configuration']).includes(source)) throw new Error('The result has an invalid evidence source.');
    const stop = hops.findIndex(h => h.tone === 'stop');
    if (stop >= 0) hops.forEach((h, i) => { if (i > stop) { h.tone = 'after'; if (!['not_applicable', 'out_of_scope', 'not_reached'].includes(h.status)) { h.status = 'not_reached'; h.note = 'Not reached after ' + hops[stop].label + '. ' + h.note; } } });
    return { hops, stop, dest: scenario.destination || scenario.channel,
      verdict: { tone: 'warn', outcome: 'conditional', text: norm(raw.summary) || (source === 'configuration' ? 'Configuration read. Live enforcement and evidence delivery are not verified.' : 'Simulation complete. Live enforcement and evidence delivery are not verified.') },
      scenario, provenance: source, limitations: (Array.isArray(raw.limitations) ? raw.limitations.map(str) : []).concat((Array.isArray(raw.errors) ? raw.errors : []).map(e => 'Read problem: ' + (typeof e === 'object' ? JSON.stringify(e) : str(e)))), corpus: raw.corpus || null };
  }
  const API = { CHANNELS, MODES, CONTROLS, normalizeInput, validateInput, contextKey, compatibleEvidence, normalizeEvent, createLedger, createSession, responseModel, statusTone };
  if (typeof module !== 'undefined' && module.exports) module.exports = API;
  else root.FlowScenario = API;
})(typeof window !== 'undefined' ? window : globalThis);
