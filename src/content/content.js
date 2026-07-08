(function initializeDownloadLinkXray() {
  "use strict";

  const BADGE_CLASS = "dlx-badge";
  const HIGHLIGHT_CLASSES = [
    "dlx-highlight-real",
    "dlx-highlight-executable",
    "dlx-highlight-suspicious",
    "dlx-highlight-unknown"
  ];
  const state = {
    enabled: true,
    globalEnabled: true,
    siteEnabled: true,
    lastSummary: null,
    observer: null,
    debounce: 0,
    marking: false
  };

  function loadSettings() {
    if (typeof chrome === "undefined" || !chrome.storage?.local) {
      return Promise.resolve({ dlxEnabled: true, dlxSiteDisabled: {} });
    }
    return chrome.storage.local.get({ dlxEnabled: true, dlxSiteDisabled: {} });
  }

  function disabledSummary(reason) {
    return {
      total: 0,
      marked: 0,
      best: null,
      suspicious: 0,
      executables: 0,
      disabled: true,
      reason
    };
  }

  function applySettings(settings) {
    const siteDisabled = settings.dlxSiteDisabled || {};
    state.globalEnabled = Boolean(settings.dlxEnabled);
    state.siteEnabled = !Boolean(siteDisabled[location.hostname]);
    state.enabled = state.globalEnabled && state.siteEnabled;

    if (state.enabled) {
      return scanAndMark();
    }

    clearMarks();
    state.lastSummary = disabledSummary(state.globalEnabled ? "site-disabled" : "global-disabled");
    return state.lastSummary;
  }

  function visibleElement(element) {
    if (!element || !(element instanceof Element)) return false;
    const rect = element.getBoundingClientRect();
    if (rect.width < 18 || rect.height < 12) return false;
    const style = window.getComputedStyle(element);
    return style.visibility !== "hidden" && style.display !== "none" && Number(style.opacity) !== 0;
  }

  function candidateHref(element) {
    if (element instanceof HTMLAnchorElement && element.href) return element.href;
    const anchor = element.closest?.("a[href]");
    if (anchor && anchor.href) return anchor.href;
    return element.getAttribute?.("data-href") ||
      element.getAttribute?.("data-url") ||
      element.getAttribute?.("data-download-url") ||
      "";
  }

  function textOf(element) {
    const pieces = [
      element.innerText,
      element.value,
      element.getAttribute?.("aria-label"),
      element.getAttribute?.("title"),
      element.querySelector?.("img")?.getAttribute("alt")
    ];
    return pieces.filter(Boolean).join(" ").replace(/\s+/g, " ").trim();
  }

  function elementToCandidate(element) {
    const rect = element.getBoundingClientRect();
    const anchor = element instanceof HTMLAnchorElement ? element : element.closest?.("a[href]");
    return {
      href: candidateHref(element),
      label: textOf(element),
      ariaLabel: element.getAttribute?.("aria-label") || "",
      title: element.getAttribute?.("title") || "",
      alt: element.querySelector?.("img")?.getAttribute("alt") || "",
      downloadAttr: Boolean(anchor?.hasAttribute("download")),
      tagName: element.tagName,
      area: Math.round(rect.width * rect.height),
      pageUrl: location.href
    };
  }

  function scanElements() {
    const selector = [
      "a[href]",
      "button",
      "[role='button']",
      "input[type='button']",
      "input[type='submit']",
      "[data-download-url]",
      "[data-href]"
    ].join(",");
    return [...document.querySelectorAll(selector)]
      .filter((element) => !element.closest(`.${BADGE_CLASS}`))
      .filter(visibleElement)
      .map((element) => ({ element, candidate: elementToCandidate(element) }));
  }

  function clearMarks() {
    document.querySelectorAll(`.${BADGE_CLASS}`).forEach((badge) => badge.remove());
    document.querySelectorAll(HIGHLIGHT_CLASSES.map((name) => `.${name}`).join(",")).forEach((element) => {
      element.classList.remove(...HIGHLIGHT_CLASSES);
      element.removeAttribute("data-dlx-score");
      element.removeAttribute("data-dlx-verdict");
      if (element.hasAttribute("data-dlx-original-title")) {
        const originalTitle = element.getAttribute("data-dlx-original-title") || "";
        if (originalTitle) element.setAttribute("title", originalTitle);
        else element.removeAttribute("title");
        element.removeAttribute("data-dlx-original-title");
      }
    });
  }

  function badgeText(result, isBest) {
    if (isBest && result.executable) return "X-Ray: executable";
    if (isBest) return "X-Ray: likely real";
    if (result.verdict === "suspicious") return "X-Ray: suspicious";
    if (result.executable) return "X-Ray: executable";
    return "X-Ray";
  }

  function badgeClass(result, isBest) {
    if (result.verdict === "suspicious") return "dlx-badge-suspicious";
    if (result.executable) return "dlx-badge-executable";
    if (isBest || result.verdict === "likely-real") return "dlx-badge-real";
    return "dlx-badge-unknown";
  }

  function addBadge(element, result, isBest) {
    if (!element || element.tagName === "INPUT") return;
    if (element.querySelector?.(`:scope > .${BADGE_CLASS}`)) return;
    const badge = document.createElement("span");
    badge.className = `${BADGE_CLASS} ${badgeClass(result, isBest)}`;
    badge.textContent = badgeText(result, isBest);
    element.appendChild(badge);
  }

  function applyMark(element, result, isBest) {
    const className = result.verdict === "suspicious"
      ? "dlx-highlight-suspicious"
      : result.executable
        ? "dlx-highlight-executable"
        : isBest || result.verdict === "likely-real"
          ? "dlx-highlight-real"
          : "dlx-highlight-unknown";

    element.classList.add(className);
    element.dataset.dlxScore = String(result.score);
    element.dataset.dlxVerdict = result.verdict;
    if (!element.hasAttribute("data-dlx-original-title")) {
      element.setAttribute("data-dlx-original-title", element.getAttribute("title") || "");
    }
    const originalTitle = element.getAttribute("data-dlx-original-title") || "";
    element.title = `${originalTitle ? `${originalTitle}\n` : ""}Download Link X-Ray: ${result.verdict}, score ${result.score}`;
    addBadge(element, result, isBest);
  }

  function scanAndMark() {
    if (!state.enabled || !globalThis.DLXScoring) {
      state.lastSummary = disabledSummary(state.globalEnabled ? "site-disabled" : "global-disabled");
      return state.lastSummary;
    }
    state.marking = true;
    try {
      clearMarks();

      const pairs = scanElements();
      const scoredPairs = pairs
        .map((pair) => ({ ...pair, result: globalThis.DLXScoring.scoreCandidate(pair.candidate) }))
        .sort((a, b) => b.result.score - a.result.score);
      const best = scoredPairs.find((pair) => pair.result.score >= 30) || null;

      scoredPairs.forEach((pair) => {
        const shouldMark = pair === best ||
          pair.result.verdict === "suspicious" ||
          pair.result.executable ||
          pair.result.score >= 44;
        if (shouldMark) applyMark(pair.element, pair.result, pair === best);
      });

      state.lastSummary = {
        total: scoredPairs.length,
        marked: scoredPairs.filter((pair) => (
          pair === best ||
          pair.result.verdict === "suspicious" ||
          pair.result.executable ||
          pair.result.score >= 44
        )).length,
        best: best ? best.result : null,
        suspicious: scoredPairs.filter((pair) => pair.result.verdict === "suspicious").length,
        executables: scoredPairs.filter((pair) => pair.result.executable).length
      };
      return state.lastSummary;
    } finally {
      window.setTimeout(() => {
        state.marking = false;
      }, 0);
    }
  }

  function scheduleScan() {
    window.clearTimeout(state.debounce);
    state.debounce = window.setTimeout(scanAndMark, 250);
  }

  function observePage() {
    state.observer?.disconnect();
    state.observer = new MutationObserver((mutations) => {
      if (state.marking) return;
      if (mutations.some((mutation) => mutation.addedNodes.length || mutation.removedNodes.length)) {
        scheduleScan();
      }
    });
    state.observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  if (typeof chrome !== "undefined" && chrome.runtime?.onMessage) {
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (!message || !message.type) return false;
      if (message.type === "dlx:rescan") {
        sendResponse(scanAndMark());
        return true;
      }
      if (message.type === "dlx:getSummary") {
        sendResponse(state.lastSummary || scanAndMark());
        return true;
      }
      if (message.type === "dlx:setEnabled") {
        state.enabled = Boolean(message.enabled);
        if (state.enabled) {
          sendResponse(scanAndMark());
        } else {
          clearMarks();
          state.lastSummary = disabledSummary("manual-disabled");
          sendResponse(state.lastSummary);
        }
        return true;
      }
      return false;
    });
  }

  if (typeof chrome !== "undefined" && chrome.storage?.onChanged) {
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName !== "local") return;
      if (changes.dlxEnabled || changes.dlxSiteDisabled) {
        loadSettings().then(applySettings);
      }
    });
  }

  loadSettings().then((settings) => {
    applySettings(settings);
    observePage();
  });
})();
