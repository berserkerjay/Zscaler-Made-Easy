import { PAGES, appUrl, destinationFromUrl, pathAnalyzerUrl, ping } from './common.js';

const $ = id => document.getElementById(id);
const open = url => { chrome.tabs.create({ url }); window.close(); };

async function main() {
  const base = await appUrl();
  $('addr').textContent = base.replace(/^https?:\/\//, '');
  [$('settings'), $('opts')].forEach(a => a.addEventListener('click', e => { e.preventDefault(); chrome.runtime.openOptionsPage(); }));

  // The tab the popup was opened on (activeTab: only on this click).
  let dest = null;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    dest = tab ? destinationFromUrl(tab.url) : null;
  } catch (e) { dest = null; }

  const up = await ping(base);
  $('status').className = 'status ' + (up.ok ? 'ok' : 'bad');
  $('status').textContent = up.ok ? 'DLP-Check is running.' : `DLP-Check is not reachable at ${base}. ${up.why}`;
  $('down').hidden = up.ok;

  if (dest) {
    $('site').hidden = false;
    $('siteName').textContent = new URL(dest).host;
    $('siteName').title = dest;
    $('analyze').disabled = !up.ok;
    $('analyze').addEventListener('click', () => open(pathAnalyzerUrl(base, dest)));
  }
  $('panel').addEventListener('click', async () => {
    try { const w = await chrome.windows.getCurrent(); await chrome.sidePanel.open({ windowId: w.id }); window.close(); } catch (e) { /* the panel is still in the browser's side panel menu */ }
  });
  const nav = $('links');
  Object.values(PAGES).forEach(p => {
    const b = document.createElement('button');
    b.type = 'button'; b.textContent = p.label; b.disabled = !up.ok;
    b.addEventListener('click', () => open(base + p.path));
    nav.appendChild(b);
  });
}
main();
