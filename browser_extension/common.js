// Shared by the popup, the options page and the background worker.
//
// The extension holds no credentials and no tenant data. It only opens
// pages of the DLP-Check app that runs on this computer, and asks the app
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

export const PAGES = {
  home: { path: '/', label: 'Open DLP-Check' },
  path: { path: '/report/path', label: 'Path analyzer' },
  live: { path: '/report/live', label: 'Live DLP feed' },
  motion: { path: '/report/motion', label: 'Flow animator' },
  help: { path: '/help', label: 'What does everything do?' },
};

// Is the app running at `base`? {ok, build} or {ok: false, why}.
export async function ping(base, timeoutMs = 2500) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(`${base}/api/ping`, { cache: 'no-store', credentials: 'omit', signal: ctrl.signal });
    if (!r.ok) return { ok: false, why: `It answered HTTP ${r.status}.` };
    let body = null;
    try { body = await r.json(); } catch (e) { body = null; }
    // DLP-Check answers {"ok": true} and nothing else (no version, by design).
    if (!body || body.ok !== true) return { ok: false, why: 'Something else is listening there, not DLP-Check.' };
    return { ok: true };
  } catch (e) {
    return { ok: false, why: e.name === 'AbortError' ? 'No answer within a few seconds.' : 'Nothing is listening there.' };
  } finally { clearTimeout(t); }
}
