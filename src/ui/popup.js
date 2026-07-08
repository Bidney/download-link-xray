function activeTab() {
  return chrome.tabs.query({ active: true, currentWindow: true }).then((tabs) => tabs[0]);
}

function sendToActiveTab(message) {
  return activeTab().then((tab) => {
    if (!tab?.id || !/^https?:\/\//.test(tab.url || "")) return null;
    return chrome.tabs.sendMessage(tab.id, message).catch(() => null);
  });
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
  best.innerHTML = "";
  const title = document.createElement("h2");
  title.textContent = "Top candidate";
  const verdict = document.createElement("p");
  verdict.textContent = `${summary.best.verdict} · score ${summary.best.score}`;
  const host = document.createElement("p");
  host.textContent = summary.best.host || summary.best.href;
  best.append(title, verdict, host);
}

async function initialize() {
  const settings = await chrome.storage.local.get({ dlxEnabled: true });
  const enabled = document.getElementById("enabled");
  enabled.checked = Boolean(settings.dlxEnabled);
  renderSummary(await sendToActiveTab({ type: "dlx:getSummary" }));

  enabled.addEventListener("change", async () => {
    await chrome.storage.local.set({ dlxEnabled: enabled.checked });
    renderSummary(await sendToActiveTab({ type: "dlx:setEnabled", enabled: enabled.checked }));
  });

  document.getElementById("rescan").addEventListener("click", async () => {
    renderSummary(await sendToActiveTab({ type: "dlx:rescan" }));
  });

  document.getElementById("options").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });
}

initialize();
