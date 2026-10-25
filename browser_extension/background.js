// Right-click menus: analyze a link, a selected hostname / URL, or the page
// itself with DLP-Check's Path analyzer. The analyzer opens with the
// destination filled in; nothing runs until Analyze is clicked there.
import { appUrl, destinationFromText, destinationFromUrl, pathAnalyzerUrl } from './common.js';

const MENUS = [
  { id: 'dlpcheck-link', title: 'Analyze this link with DLP-Check', contexts: ['link'] },
  { id: 'dlpcheck-selection', title: 'Analyze "%s" with DLP-Check', contexts: ['selection'] },
  { id: 'dlpcheck-page', title: 'Analyze this site with DLP-Check', contexts: ['page'] },
];

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => MENUS.forEach(m => chrome.contextMenus.create(Object.assign({ documentUrlPatterns: ['http://*/*', 'https://*/*'] }, m))));
});

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
