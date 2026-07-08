async function initialize() {
  const backend = document.getElementById("backend");
  const status = document.getElementById("status");
  const settings = await chrome.storage.local.get({ dlxBackendUrl: "" });
  backend.value = settings.dlxBackendUrl || "";

  document.getElementById("save").addEventListener("click", async () => {
    const value = backend.value.trim().replace(/\/+$/, "");
    if (value && !/^https?:\/\/.+/i.test(value)) {
      status.textContent = "Use an http:// or https:// URL.";
      status.style.color = "#bd2c2c";
      return;
    }
    await chrome.storage.local.set({ dlxBackendUrl: value });
    status.textContent = "Saved.";
    status.style.color = "#16823a";
  });
}

initialize();
