// Shared by the popup, the options page and the background worker.
//
// The extension holds no credentials and no tenant data. It only opens
// pages of the Zscaler Made Easy app that runs on this computer, and asks the app
// whether it is running (GET /api/ping, which needs no sign-in). Signing
// in, the UI token, write mode and every tenant read stay in the app.

export const DEFAULT_APP = 'http://127.0.0.1:8000';
const MAX_DEST = 2048;

// The app's address: http on loopback only (127.0.0.1, localhost or [::1])
// with an optional port, never anything else, so a mistyped or hostile
// setting cannot send a destination off this computer.
export function normalizeAppUrl(input) {
  let u;
  try { u = new URL(String(input || '').trim()); } catch (e) { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname)) return null;
  if (u.username || u.password) return null;
  return `${u.protocol}//${u.host}`;
}

export async function appUrl() {
  try {
    const { app } = await chrome.storage.sync.get('app');
    return normalizeAppUrl(app) || DEFAULT_APP;
  } catch (e) { return DEFAULT_APP; }
}

// What the Path analyzer gets for a page or link: scheme, host and path.
// The query string and fragment are dropped (they often carry session
// tokens or personal data) and only http(s) pages are analyzable.
export function destinationFromUrl(raw) {
  let u;
  try { u = new URL(String(raw || '')); } catch (e) { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (!u.hostname) return null;
  const dest = `${u.protocol}//${u.host}${u.pathname === '/' ? '' : u.pathname}`;
  return dest.slice(0, MAX_DEST);
}

// Selected text: a URL, a hostname or an IP address, else nothing. One
// token only, so a selected paragraph is never sent anywhere.
export function destinationFromText(text) {
  const t = String(text || '').trim();
  if (!t || t.length > MAX_DEST || /\s/.test(t)) return null;
  if (/^https?:\/\//i.test(t)) return destinationFromUrl(t);
  const host = t.replace(/\/.*$/, '');
  const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  const name = /^(?=.{1,253}$)(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
  if (!ipv4.test(host) && !name.test(host)) return null;
  return t.replace(/[?#].*$/, '');
}

export function pathAnalyzerUrl(base, dest) {
  return `${base}/report/path${dest ? `?d=${encodeURIComponent(dest)}` : ''}`;
}

// The ZIA admin consoles (one per Zscaler cloud, as zscaler_clouds.py lists
// them). The in-console badges run only on these, and only after the admin
// switches them on in the extension's settings (an optional permission).
export const CONSOLE_ORIGINS = [
  'https://admin.zscaler.net/*', 'https://admin.zscalerone.net/*', 'https://admin.zscalertwo.net/*',
  'https://admin.zscalerthree.net/*', 'https://admin.zscloud.net/*', 'https://admin.zscalerten.net/*',
  'https://admin.zscalerbeta.net/*', 'https://admin.zscalergov.net/*', 'https://admin.zscalergov.us/*',
];
export const CONSOLE_SCRIPT_ID = 'dlpcheck-console-badges';

// A call to the app's API. The app's own sign-in (its UI token cookie, set
// when Zscaler Made Easy was opened in this browser) authenticates it; the
// extension never holds a token. POSTs are accepted from the extension
// only on the app's read-only endpoints for it.
export async function api(base, path, body) {
  const r = await fetch(base + path, {
    method: body === undefined ? 'GET' : 'POST', credentials: 'include', cache: 'no-store',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try { data = await r.json(); } catch (e) { data = null; }
  if (!r.ok) {
    const d = data && data.detail;
    const why = r.status === 401 ? 'Sign in: open Zscaler Made Easy in this browser first (it unlocks the app for the extension too).'
      : (typeof d === 'string' ? d : (d && (d.cause || d.message)) || `HTTP ${r.status}`);
    const err = new Error(why); err.status = r.status; throw err;
  }
  return data;
}

// The binary answer of a finished job (a zip), for a download link.
export async function apiBlob(base, path) {
  const r = await fetch(base + path, { credentials: 'include', cache: 'no-store' });
  if (!r.ok) throw new Error(r.status === 404 ? 'The file is no longer kept; run the export again.' : `HTTP ${r.status}`);
  const cd = r.headers.get('Content-Disposition') || '';
  const m = /filename="([^"]+)"/.exec(cd);
  return { blob: await r.blob(), name: m ? m[1] : 'export.zip' };
}

// One key per object, the same in the panel, the badges and the stage
// (the app sends it; an index read before it did is keyed the old way).
export const objectKey = o => o.key || `${o.kind}:${o.kind === 'rule' ? `${o.channel}:` : ''}${o.name}`;

export const PAGES = {
  home: { path: '/', label: 'Open Zscaler Made Easy' },
  path: { path: '/report/path', label: 'Path analyzer' },
  live: { path: '/report/live', label: 'Live DLP feed' },
  motion: { path: '/report/motion', label: 'Flow animator' },
  shadow: { path: '/report/shadow', label: 'Shadowed rules' },
  help: { path: '/help', label: 'What does everything do?' },
};

// The kinds of object the index holds (the app sends the same list as
// `kinds`; this is the fallback for an index read by an older app).
export const KINDS = {
  dictionary: { label: 'DLP dictionary', plural: 'DLP dictionaries', group: 'DLP', export: true },
  engine: { label: 'DLP engine', plural: 'DLP engines', group: 'DLP', export: true },
  rule: { label: 'DLP rule', plural: 'DLP rules', group: 'DLP', export: true },
};
export function kindInfo(index, kind) {
  const k = ((index && index.kinds) || []).find(x => x.kind === kind) || KINDS[kind];
  return k || { label: String(kind || 'object').replace(/_/g, ' '), plural: String(kind || 'object').replace(/_/g, ' ') + 's', group: 'Objects', export: false };
}
// Rule kinds the Shadowed rules page analyses (File Type Control is not one).
export const SHADOW_KINDS = ['rule', 'url_rule', 'cac_rule', 'ssl_rule', 'firewall_rule'];
const POLICY_RULE_KINDS = ['url_rule', 'cac_rule', 'ssl_rule', 'firewall_rule', 'ftc_rule'];

const SEV_RANK = { high: 3, medium: 2, low: 1, info: 0 };
const n = (x, one, many) => `${x} ${x === 1 ? one : (many || one + 's')}`;

// What a console badge says about an object: its most serious finding
// ("shadowed", "monitor only", "unused"), else what uses it ("used in 4
// rules") or, for a rule, where it sits ("order 3 · block").
export function badgeLabel(o) {
  const findings = o.findings || [];
  const sev = findings.reduce((a, f) => (SEV_RANK[f.severity] > SEV_RANK[a] ? f.severity : a), 'info');
  const top = findings.find(f => f.severity === sev);
  const c = o.counts || {};
  let label;
  if (top && sev !== 'info') label = top.short || top.text.split(':')[0].split('.')[0].toLowerCase();
  else if (o.kind === 'dictionary') label = c.engines ? `${n(c.engines, 'engine')}, ${n(c.rules || 0, 'rule')}` : 'unused';
  else if (o.kind === 'engine') label = c.rules ? n(c.rules, 'rule') : 'unused';
  else if (o.kind === 'rule') label = String(o.state || '').toLowerCase() === 'disabled' ? 'disabled' : n(c.engines || 0, 'engine');
  else if (POLICY_RULE_KINDS.includes(o.kind)) {
    const act = String(o.action || (o.actions || [])[0] || '').toLowerCase().replace(/_/g, ' ');
    label = String(o.state || '').toLowerCase() === 'disabled' ? 'disabled'
      : [o.order !== undefined && o.order !== null ? `order ${o.order}` : '', act].filter(Boolean).join(' · ') || 'rule';
  } else label = c.rules ? `used in ${n(c.rules, 'rule')}` : 'unused';
  return { label: label.slice(0, 40), sev };
}

// Is the app running at `base`? {ok, build} or {ok: false, why}.
export async function ping(base, timeoutMs = 2500) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(`${base}/api/ping`, { cache: 'no-store', credentials: 'omit', signal: ctrl.signal });   // the one unauthenticated call
    if (!r.ok) return { ok: false, why: `It answered HTTP ${r.status}.` };
    let body = null;
    try { body = await r.json(); } catch (e) { body = null; }
    // Zscaler Made Easy answers {"ok": true} and nothing else (no version, by design).
    if (!body || body.ok !== true) return { ok: false, why: 'Something else is listening there, not Zscaler Made Easy.' };
    return { ok: true };
  } catch (e) {
    return { ok: false, why: e.name === 'AbortError' ? 'No answer within a few seconds.' : 'Nothing is listening there.' };
  } finally { clearTimeout(t); }
}
