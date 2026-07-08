function activeTab() {
  return chrome.tabs.query({ active: true, currentWindow: true }).then((tabs) => tabs[0]);
}

function hostnameFromTab(tab) {
  try {
    const url = new URL(tab?.url || "");
    if (url.protocol !== "http:" && url.protocol !== "https:") return "";
    return url.hostname;
  } catch (_error) {
    return "";
  }
}

function sendToActiveTab(message) {
  return activeTab().then((tab) => {
    if (!tab?.id || !/^https?:\/\//.test(tab.url || "")) return null;
    return chrome.tabs.sendMessage(tab.id, message).catch(() => null);
  });
}

function disabledSummary(message) {
  return {
    marked: 0,
    suspicious: 0,
    executables: 0,
    best: null,
    message
  };
}

function renderSummary(summary) {
  document.getElementById("marked").textContent = String(summary?.marked ?? 0);
  document.getElementById("suspicious").textContent = String(summary?.suspicious ?? 0);
  document.getElementById("executables").textContent = String(summary?.executables ?? 0);

  const best = document.getElementById("best");
  if (!summary?.best) {
    best.classList.add("hidden");
    best.textContent = "";
    return;
  }

  best.classList.remove("hidden");
  best.replaceChildren();
  const title = document.createElement("h2");
  title.textContent = "Top candidate";
  const verdict = document.createElement("p");
  verdict.textContent = `${summary.best.verdict} · score ${summary.best.score}`;
  const host = document.createElement("p");
  host.textContent = summary.best.host || summary.best.href;
  best.append(title, verdict, host);
}

async function refreshActiveTab(globalEnabled, siteEnabled) {
  const effectiveEnabled = Boolean(globalEnabled && siteEnabled);
  if (!effectiveEnabled) {
    await sendToActiveTab({ type: "dlx:setEnabled", enabled: false });
    renderSummary(disabledSummary("Disabled"));
    return;
  }
  renderSummary(await sendToActiveTab({ type: "dlx:setEnabled", enabled: true }));
}

async function initialize() {
  const tab = await activeTab();
  const hostname = hostnameFromTab(tab);
  const settings = await chrome.storage.local.get({ dlxEnabled: true, dlxSiteDisabled: {} });
  const enabled = document.getElementById("enabled");
  const siteEnabled = document.getElementById("siteEnabled");
  const siteLabel = document.getElementById("siteLabel");
  const status = document.getElementById("status");
  const siteDisabled = settings.dlxSiteDisabled || {};

  enabled.checked = Boolean(settings.dlxEnabled);
  siteEnabled.checked = hostname ? !Boolean(siteDisabled[hostname]) : false;
  siteEnabled.disabled = !hostname;
  siteLabel.textContent = hostname || "Unavailable on this page";
  status.textContent = hostname ? "" : "Open a normal website tab to use per-site controls.";
  renderSummary(await sendToActiveTab({ type: "dlx:getSummary" }));

  enabled.addEventListener("change", async () => {
    await chrome.storage.local.set({ dlxEnabled: enabled.checked });
    status.textContent = enabled.checked ? "" : "Disabled globally.";
    await refreshActiveTab(enabled.checked, siteEnabled.checked);
  });

  siteEnabled.addEventListener("change", async () => {
    if (!hostname) return;
    const latest = await chrome.storage.local.get({ dlxSiteDisabled: {} });
    const nextDisabled = { ...(latest.dlxSiteDisabled || {}) };
    if (siteEnabled.checked) {
      delete nextDisabled[hostname];
      status.textContent = `Enabled on ${hostname}.`;
    } else {
      nextDisabled[hostname] = true;
      status.textContent = `Disabled on ${hostname}.`;
    }
    await chrome.storage.local.set({ dlxSiteDisabled: nextDisabled });
    await refreshActiveTab(enabled.checked, siteEnabled.checked);
  });

  document.getElementById("rescan").addEventListener("click", async () => {
    await refreshActiveTab(enabled.checked, siteEnabled.checked);
  });

  document.getElementById("options").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });
}

initialize();
