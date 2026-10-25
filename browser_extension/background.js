// The service worker: right-click menus, the in-console badges (an opt-in
// content script on the ZIA admin console) and the side panel.
import { CONSOLE_ORIGINS, CONSOLE_SCRIPT_ID, appUrl, destinationFromText, destinationFromUrl, objectKey, pathAnalyzerUrl } from './common.js';

const MENUS = [
  { id: 'dlpcheck-link', title: 'Analyze this link with DLP-Check', contexts: ['link'] },
  { id: 'dlpcheck-selection', title: 'Analyze "%s" with DLP-Check', contexts: ['selection'] },
  { id: 'dlpcheck-page', title: 'Analyze this site with DLP-Check', contexts: ['page'] },
];

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => MENUS.forEach(m => chrome.contextMenus.create(Object.assign({ documentUrlPatterns: ['http://*/*', 'https://*/*'] }, m))));
  syncConsoleScript();
});
chrome.runtime.onStartup.addListener(syncConsoleScript);

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  let dest = null;
  if (info.menuItemId === 'dlpcheck-link') dest = destinationFromUrl(info.linkUrl);
  else if (info.menuItemId === 'dlpcheck-selection') dest = destinationFromText(info.selectionText);
  else if (info.menuItemId === 'dlpcheck-page') dest = destinationFromUrl(info.pageUrl || (tab && tab.url));
  const base = await appUrl();
  // A selection that is not a URL, hostname or IP opens the analyzer empty
  // rather than sending the text anywhere.
  chrome.tabs.create({ url: pathAnalyzerUrl(base, dest), index: tab ? tab.index + 1 : undefined });
});

// ── In-console badges: registered only while the admin allows the console origins ──
async function syncConsoleScript() {
  let allowed = false;
  try { allowed = await chrome.permissions.contains({ origins: CONSOLE_ORIGINS }); } catch (e) { allowed = false; }
  let registered = [];
  try { registered = await chrome.scripting.getRegisteredContentScripts({ ids: [CONSOLE_SCRIPT_ID] }); } catch (e) { registered = []; }
  if (allowed && !registered.length) {
    await chrome.scripting.registerContentScripts([{ id: CONSOLE_SCRIPT_ID, matches: CONSOLE_ORIGINS, js: ['console.js'], runAt: 'document_idle', allFrames: true, persistAcrossSessions: true }]);
  } else if (!allowed && registered.length) {
    await chrome.scripting.unregisterContentScripts({ ids: [CONSOLE_SCRIPT_ID] });
  }
}
chrome.permissions.onAdded.addListener(syncConsoleScript);
chrome.permissions.onRemoved.addListener(syncConsoleScript);

// What a badge says, by exact object name: from the index the side panel
// read through DLP-Check (kept in session storage, gone when the browser closes).
function badgeEntry(o) {
  const order = { high: 3, medium: 2, low: 1, info: 0 };
  const sev = (o.findings || []).reduce((a, f) => (order[f.severity] > order[a] ? f.severity : a), 'info');
  const top = (o.findings || []).find(f => f.severity === sev);
  let label;
  if (sev === 'high' || sev === 'medium') label = top.text.split(':')[0].split('.')[0].toLowerCase();
  else if (o.kind === 'dictionary') label = o.counts.engines ? `${o.counts.engines} engine${o.counts.engines === 1 ? '' : 's'}, ${o.counts.rules} rule${o.counts.rules === 1 ? '' : 's'}` : 'unused';
  else if (o.kind === 'engine') label = o.counts.rules ? `${o.counts.rules} rule${o.counts.rules === 1 ? '' : 's'}` : 'unused';
  else label = String(o.state || '').toLowerCase() === 'disabled' ? 'disabled' : `${o.counts.engines} engine${o.counts.engines === 1 ? '' : 's'}`;
  return { key: objectKey(o), kind: o.kind, label: label.slice(0, 40), sev };
}
async function namesMap() {
  let index = null;
  try { index = (await chrome.storage.session.get('index')).index; } catch (e) { index = null; }
  if (!index || !Array.isArray(index.objects)) return null;
  const names = {};
  index.objects.forEach(o => { (names[o.name] = names[o.name] || []).push(badgeEntry(o)); });
  return names;
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (!msg || typeof msg.type !== 'string') return false;
  if (msg.type === 'names') { namesMap().then(names => reply({ names })); return true; }
  if (msg.type === 'focus' && typeof msg.key === 'string' && sender.tab) {
    // Open the panel on the clicked object (a click is the user gesture the panel needs).
    chrome.sidePanel.open({ tabId: sender.tab.id }).catch(() => {});
    chrome.storage.session.set({ focus: { key: msg.key.slice(0, 600), at: Date.now() } });
    return false;
  }
  if (msg.type === 'index-updated') {
    chrome.tabs.query({ url: CONSOLE_ORIGINS }).then(tabs => tabs.forEach(t => chrome.tabs.sendMessage(t.id, { type: 'refresh' }).catch(() => {}))).catch(() => {});
    return false;
  }
  return false;
});
