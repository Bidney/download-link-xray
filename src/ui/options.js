async function initialize() {
  const backend = document.getElementById("backend");
  const backendToken = document.getElementById("backendToken");
  const status = document.getElementById("status");
  const settings = await chrome.storage.local.get({ dlxBackendUrl: "", dlxBackendToken: "" });
  backend.value = settings.dlxBackendUrl || "";
  backendToken.value = settings.dlxBackendToken || "";

  document.getElementById("save").addEventListener("click", async () => {
    const validation = globalThis.DLXBackendUrl.validateBackendUrl(backend.value, { allowEmpty: true });
    if (!validation.ok) {
      status.textContent = validation.error;
      status.style.color = "#bd2c2c";
      return;
    }
    const originPattern = validation.value
      ? globalThis.DLXBackendUrl.backendOriginPattern(validation.value)
      : "";
    if (originPattern) {
      const granted = await chrome.permissions.request({ origins: [originPattern] });
      if (!granted) {
        status.textContent = "Backend host permission was not granted.";
        status.style.color = "#bd2c2c";
        return;
      }
    }
    await chrome.storage.local.set({
      dlxBackendUrl: validation.value,
      dlxBackendToken: backendToken.value.trim()
    });
    status.textContent = "Saved.";
    status.style.color = "#16823a";
  });
}

initialize();
