const params = new URLSearchParams(location.search);
const inspectedUrl = params.get("url") || "";
const pageUrl = params.get("page") || "";
const mode = params.get("mode") || "inspect";

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function appendList(parent, title, items) {
  if (!items?.length) return;
  parent.append(el("h3", title));
  const list = document.createElement("ul");
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    list.append(li);
  });
  parent.append(list);
}

function verdictClass(result) {
  if (result.verdict === "suspicious") return "bad";
  if (result.executable) return "warn";
  return "good";
}

function renderLocal(result) {
  const container = document.getElementById("local");
  container.replaceChildren();
  container.append(el("h2", "Local link analysis"));
  const badge = el("span", `${result.verdict} · score ${result.score}`, `badge ${verdictClass(result)}`);
  container.append(badge);
  container.append(el("p", result.href));
  if (result.fileName) container.append(el("p", `File: ${result.fileName}`));
  if (result.host) container.append(el("p", `Host: ${result.host}`));
  if (result.executable) container.append(el("p", "Executable-style target. Treat this as higher risk.", "muted"));
  appendList(container, "Positive signals", result.reasons);
  appendList(container, "Warnings", result.warnings);
  const vtUrl = `https://www.virustotal.com/gui/url/${globalThis.DLXScoring.virusTotalUrlId(result.href)}`;
  const link = el("a", "Open VirusTotal URL page", "button");
  link.href = vtUrl;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  container.append(link);
}

function vtStats(verdict) {
  const stats = verdict?.data?.attributes?.last_analysis_stats;
  if (!stats) return "No VirusTotal verdict available.";
  return `VirusTotal: ${stats.malicious || 0} malicious, ${stats.suspicious || 0} suspicious, ${stats.harmless || 0} harmless, ${stats.undetected || 0} undetected.`;
}

function renderBackend(data) {
  const container = document.getElementById("backend");
  container.replaceChildren();
  container.append(el("h2", "Backend inspection"));
  if (!data.ok) {
    container.append(el("p", data.error || "Backend check failed.", "muted"));
    return;
  }

  container.append(el("p", `Final URL: ${data.finalUrl || data.url}`));
  if (data.status) container.append(el("p", `HTTP status: ${data.status}`));
  if (data.contentType) container.append(el("p", `Content-Type: ${data.contentType}`));
  if (data.contentLength) container.append(el("p", `Content-Length: ${data.contentLength}`));
  if (data.redirects?.length) {
    container.append(el("h3", "Redirect chain"));
    const pre = el("pre", data.redirects.map((item, index) => `${index + 1}. ${item.status} ${item.from} -> ${item.to}`).join("\n"));
    container.append(pre);
  }
  container.append(el("p", vtStats(data.virusTotalUrl), "muted"));
  if (data.sha256) {
    container.append(el("p", `SHA-256: ${data.sha256}`));
    const fileLink = el("a", "Open VirusTotal file page", "button");
    fileLink.href = `https://www.virustotal.com/gui/file/${data.sha256}`;
    fileLink.target = "_blank";
    fileLink.rel = "noopener noreferrer";
    container.append(fileLink);
  }
  if (data.virusTotalFile) {
    container.append(el("p", vtStats(data.virusTotalFile), "muted"));
  }
  if (data.notes?.length) appendList(container, "Notes", data.notes);
}

async function checkBackend() {
  const container = document.getElementById("backend");
  const settings = await chrome.storage.local.get({ dlxBackendUrl: "", dlxBackendToken: "" });
  if (!settings.dlxBackendUrl) {
    container.replaceChildren();
    container.append(el("h2", "Backend inspection"));
    container.append(el("p", "Configure a backend URL in Options for redirect following, hashing, and VirusTotal API checks.", "muted"));
    const options = el("button", "Open options");
    options.addEventListener("click", () => chrome.runtime.openOptionsPage());
    container.append(options);
    return;
  }

  const validation = globalThis.DLXBackendUrl.validateBackendUrl(settings.dlxBackendUrl, { allowEmpty: false });
  if (!validation.ok) {
    renderBackend({ ok: false, error: validation.error });
    return;
  }
  const originPattern = globalThis.DLXBackendUrl.backendOriginPattern(validation.value);
  if (originPattern) {
    const hasPermission = await chrome.permissions.contains({ origins: [originPattern] });
    if (!hasPermission) {
      renderBackend({ ok: false, error: "Backend host permission missing. Open Options and save the backend URL again." });
      return;
    }
  }

  container.replaceChildren();
  container.append(el("h2", "Backend inspection"));
  container.append(el("p", "Checking..."));
  const apiUrl = new URL("/inspect", validation.value);
  apiUrl.searchParams.set("url", inspectedUrl);
  apiUrl.searchParams.set("deep", mode === "deep" ? "1" : "0");
  const headers = { "x-dlx-client": "download-link-xray" };
  if (settings.dlxBackendToken) headers["x-dlx-token"] = settings.dlxBackendToken;
  const response = await fetch(apiUrl.href, { cache: "no-store", headers });
  const data = await response.json();
  renderBackend(data);
}

async function initialize() {
  document.getElementById("mode").textContent = mode === "deep"
    ? "Executable risk check"
    : "Download link inspection";
  const result = globalThis.DLXScoring.scoreCandidate({
    href: inspectedUrl,
    pageUrl,
    label: "",
    title: "",
    ariaLabel: ""
  });
  renderLocal(result);
  try {
    await checkBackend();
  } catch (error) {
    renderBackend({ ok: false, error: error.message });
  }
}

initialize();
