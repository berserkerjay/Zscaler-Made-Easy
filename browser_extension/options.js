import { CONSOLE_ORIGINS, DEFAULT_APP, appUrl, normalizeAppUrl, ping } from './common.js';

const $ = id => document.getElementById(id);
const say = (text, ok) => { $('msg').textContent = text; $('msg').className = 'status ' + (ok ? 'ok' : 'bad'); };

async function save(value) {
  const base = normalizeAppUrl(value);
  if (!base) { say('Use an http address on this computer, such as http://127.0.0.1:8000.', false); return; }
  await chrome.storage.sync.set({ app: base });
  $('app').value = base;
  const up = await ping(base);
  say(up.ok ? `Saved. DLP-Check answers at ${base}.` : `Saved, but DLP-Check does not answer at ${base}: ${up.why}`, up.ok);
}
appUrl().then(v => { $('app').value = v; });
$('save').addEventListener('click', () => save($('app').value));
$('reset').addEventListener('click', () => save(DEFAULT_APP));
$('app').addEventListener('keydown', e => { if (e.key === 'Enter') save($('app').value); });

// Badges: an optional permission for the console origins, asked for only
// here, on a click (the browser shows its own prompt).
const badgeSay = (text, ok) => { $('badgeMsg').textContent = text; $('badgeMsg').className = 'status ' + (ok ? 'ok' : ''); };
async function badgeState() {
  const on = await chrome.permissions.contains({ origins: CONSOLE_ORIGINS });
  $('badgesOn').disabled = on; $('badgesOff').disabled = !on;
  badgeSay(on ? 'Badges are on for the ZIA admin console. Open the side panel and read the tenant to fill them.' : 'Badges are off.', on);
}
$('badgesOn').addEventListener('click', async () => {
  const ok = await chrome.permissions.request({ origins: CONSOLE_ORIGINS });
  if (!ok) badgeSay('The browser did not allow it; the badges stay off.', false);
  await badgeState();
});
$('badgesOff').addEventListener('click', async () => { await chrome.permissions.remove({ origins: CONSOLE_ORIGINS }); await badgeState(); });
badgeState();
