// HAR import for the Path analyzer: reads a HAR file IN THE BROWSER and
// keeps only what the analyzer needs per host. A HAR file holds cookies,
// authorization headers, URL paths and query strings and request bodies;
// none of that leaves this function: the result carries host names,
// schemes, request counts, the HTTP methods seen, whether an upload
// happened (a POST or PUT with a body larger than zero) and the bytes the
// request bodies carried. The file itself is never uploaded.
//
//   HarParse.parse(text, { maxBytes, maxHosts }) -> {
//     ok, error,                 // ok false with a sentence when the file cannot be read
//     entries, skipped,          // entries seen; entries with no usable http(s) URL
//     hosts: [{ host, schemes, requests, methods, uploads, bytes_sent }],   // the ones to analyze (at most maxHosts)
//     more: [{ host, requests, uploads }],   // the hosts over the cap, listed (at most MAX_MORE), not analyzed
//     more_total,                // every host over the cap, listed or not
//     untracked,                 // entries for hosts past MAX_TRACKED distinct hosts: counted, not kept
//     total_hosts, capped }
//   HarParse.MAX_BYTES, HarParse.MAX_HOSTS
//
// Runs in the page (window.HarParse) and under node for the tests
// (module.exports). Never evaluates anything from the file.
(function (root) {
  'use strict';
  const MAX_BYTES = 100 * 1024 * 1024;
  const MAX_HOSTS = 200;
  // A capture can name hundreds of thousands of hosts: the ones over MAX_TRACKED are
  // counted, not kept, and the list of hosts left out is cut at MAX_MORE (the page draws it).
  const MAX_TRACKED = 20000;
  const MAX_MORE = 1000;
  const SCHEMES = { 'http:': 'http', 'https:': 'https', 'ws:': 'ws', 'wss:': 'wss' };
  const UPLOAD = { POST: true, PUT: true };
  const HOST_RE = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

  function fail(error) {
    return { ok: false, error, entries: 0, skipped: 0, hosts: [], more: [], more_total: 0, untracked: 0, total_hosts: 0, capped: false };
  }

  // The host and scheme of a URL, or null. Only the host leaves here: the
  // path, query, fragment, user and password are never kept.
  function hostOf(url) {
    if (typeof url !== 'string' || url.length > 65536) return null;
    let u;
    try { u = new URL(url); } catch (e) { return null; }
    const scheme = SCHEMES[u.protocol];
    if (!scheme) return null;
    let h = String(u.hostname || '').toLowerCase().replace(/\.$/, '');
    if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
    if (!h) return null;
    if (!(HOST_RE.test(h) || IPV4_RE.test(h) || (h.includes(':') && /^[0-9a-f:.]+$/.test(h)))) return null;
    return { host: h, scheme };
  }

  // Bytes a request body carried: HAR's bodySize when it is known (>= 0),
  // else the size of postData.text. The text itself is never kept.
  function bodyBytes(req) {
    const n = Number(req && req.bodySize);
    // A body is at most the file it came from: a claimed size past that is capped, so a sum stays finite.
    if (Number.isFinite(n) && n >= 0) return Math.min(Math.floor(n), MAX_BYTES);
    const pd = req && req.postData;
    if (pd && typeof pd.text === 'string') {
      try { return new TextEncoder().encode(pd.text).length; } catch (e) { return pd.text.length; }
    }
    return 0;
  }

  function parse(text, opts) {
    const o = opts || {};
    const maxBytes = Number(o.maxBytes) > 0 ? Number(o.maxBytes) : MAX_BYTES;
    const maxHosts = Number(o.maxHosts) > 0 ? Math.floor(Number(o.maxHosts)) : MAX_HOSTS;
    if (typeof text !== 'string' || !text.trim()) return fail('The file is empty.');
    // String length counts UTF-16 code units: at most 2 per byte, a safe bound before parsing.
    if (text.length > maxBytes) return fail(`The file is larger than ${Math.round(maxBytes / 1048576)} MB, the most this page reads. Export a shorter capture.`);
    let har;
    try { har = JSON.parse(text); } catch (e) { return fail('This is not a HAR file: it is not valid JSON. Export it again from the browser\'s developer tools (Network tab, Save all as HAR).'); }
    const log = har && typeof har === 'object' ? har.log : null;
    if (!log || typeof log !== 'object') return fail('This is not a HAR file: it has no "log" section.');
    if (!Array.isArray(log.entries)) return fail('This is not a HAR file: its log has no list of entries.');
    if (!log.entries.length) return fail('The HAR file has no requests in it. Record the traffic again with the Network tab open, then save it.');
    const by = new Map();
    let skipped = 0, untracked = 0;
    for (const entry of log.entries) {
      const req = entry && typeof entry === 'object' ? entry.request : null;
      const hs = req && typeof req === 'object' ? hostOf(req.url) : null;
      if (!hs) { skipped++; continue; }
      let h = by.get(hs.host);
      if (!h && by.size >= MAX_TRACKED) { untracked++; continue; }
      if (!h) { h = { host: hs.host, schemes: [], requests: 0, methods: [], uploads: 0, bytes_sent: 0 }; by.set(hs.host, h); }
      if (!h.schemes.includes(hs.scheme)) h.schemes.push(hs.scheme);
      h.requests++;
      const m = String(req.method || '').toUpperCase();
      if (/^[A-Z]{1,12}$/.test(m) && !h.methods.includes(m) && h.methods.length < 12) h.methods.push(m);
      const b = bodyBytes(req);
      h.bytes_sent += b;
      if (UPLOAD[m] && b > 0) h.uploads++;
    }
    if (!by.size) return fail('The HAR file names no web host (http or https) the analyzer can read.');
    // Uploads first (that is where data leaves), then the most bytes sent, then the busiest.
    const all = Array.from(by.values()).sort((a, b) => (b.uploads - a.uploads) || (b.bytes_sent - a.bytes_sent) || (b.requests - a.requests) || a.host.localeCompare(b.host));
    const hosts = all.slice(0, maxHosts);
    const rest = all.slice(maxHosts);
    const more = rest.slice(0, MAX_MORE).map(h => ({ host: h.host, requests: h.requests, uploads: h.uploads }));
    return { ok: true, error: null, entries: log.entries.length, skipped, hosts, more, more_total: rest.length, untracked,
      total_hosts: all.length, capped: rest.length > 0 || untracked > 0 };
  }

  const api = { parse, hostOf, MAX_BYTES, MAX_HOSTS, MAX_TRACKED, MAX_MORE };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.HarParse = api;
})(typeof window !== 'undefined' ? window : this);
