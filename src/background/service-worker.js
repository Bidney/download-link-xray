importScripts("../shared/scoring.js");

const MENU_INSPECT = "dlx-inspect-link";
const MENU_DEEP = "dlx-deep-check";

function createMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU_INSPECT,
      title: "Inspect download link",
      contexts: ["link"],
      targetUrlPatterns: ["http://*/*", "https://*/*"]
    });
    chrome.contextMenus.create({
      id: MENU_DEEP,
      title: "Check executable risk",
      contexts: ["link"],
      targetUrlPatterns: ["http://*/*", "https://*/*"]
    });
  });
}

function openInspector(linkUrl, pageUrl, mode) {
  const params = new URLSearchParams({
    url: linkUrl || "",
    page: pageUrl || "",
    mode: mode || "inspect"
  });
  chrome.windows.create({
    url: chrome.runtime.getURL(`src/ui/inspect.html?${params.toString()}`),
    type: "popup",
    width: 520,
    height: 760
  });
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get({ dlxEnabled: true }, (settings) => {
    chrome.storage.local.set({ dlxEnabled: settings.dlxEnabled });
  });
  createMenus();
});

chrome.runtime.onStartup.addListener(createMenus);

chrome.contextMenus.onClicked.addListener((info) => {
  if (!info.linkUrl) return;
  if (info.menuItemId === MENU_DEEP) {
    openInspector(info.linkUrl, info.pageUrl, "deep");
    return;
  }
  if (info.menuItemId === MENU_INSPECT) {
    openInspector(info.linkUrl, info.pageUrl, "inspect");
  }
});
