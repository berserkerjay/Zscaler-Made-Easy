import { DEFAULT_APP, appUrl, normalizeAppUrl, ping } from './common.js';

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
