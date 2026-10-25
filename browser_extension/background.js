// The service worker: right-click menus, the in-console badges (an opt-in
// content script on the ZIA admin console) and the side panel.
import { CONSOLE_ORIGINS, CONSOLE_SCRIPT_ID, appUrl, badgeLabel, destinationFromText, destinationFromUrl, kindInfo, objectKey, pathAnalyzerUrl } from './common.js';

const MENUS = [
  { id: 'dlpcheck-link', title: 'Analyze this link with Zscaler Made Easy', contexts: ['link'] },
  { id: 'dlpcheck-selection', title: 'Analyze "%s" with Zscaler Made Easy', contexts: ['selection'] },
  { id: 'dlpcheck-page', title: 'Analyze this site with Zscaler Made Easy', contexts: ['page'] },
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
// read through Zscaler Made Easy (kept in session storage, gone when the browser closes).
function badgeEntry(index, o) {
  const { label, sev } = badgeLabel(o);
  return { key: objectKey(o), kind: kindInfo(index, o.kind).label, label, sev };
}
async function namesMap() {
  let index = null;
  try { index = (await chrome.storage.session.get('index')).index; } catch (e) { index = null; }
  if (!index || !Array.isArray(index.objects)) return null;
  const names = {};
  index.objects.forEach(o => { (names[o.name] = names[o.name] || []).push(badgeEntry(index, o)); });
  return names;
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (!msg || typeof msg.type !== 'string') return false;
  if (msg.type === 'names') { namesMap().then(names => reply({ names })); return true; }
  if (msg.type === 'focus' && sender.tab) {
    // Open the panel on the clicked object, or on the list of objects that
    // share the name (a click is the user gesture the panel needs).
    const keys = (Array.isArray(msg.keys) ? msg.keys : [msg.key]).filter(k => typeof k === 'string').slice(0, 20).map(k => k.slice(0, 600));
    if (!keys.length) return false;
    chrome.sidePanel.open({ tabId: sender.tab.id }).catch(() => {});
    chrome.storage.session.set({ focus: { key: keys[0], keys, at: Date.now() } });
    return false;
  }
  if (msg.type === 'index-updated') {
    chrome.tabs.query({ url: CONSOLE_ORIGINS }).then(tabs => tabs.forEach(t => chrome.tabs.sendMessage(t.id, { type: 'refresh' }).catch(() => {}))).catch(() => {});
    return false;
  }
  return false;
});
