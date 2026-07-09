#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const dns = require("dns/promises");
const http = require("http");
const https = require("https");
const net = require("net");
const { URL } = require("url");
const scoring = require("../src/shared/scoring");

const PORT = Number(process.env.PORT || 8787);
const VT_API_KEY = process.env.VT_API_KEY || "";
const BACKEND_TOKEN = process.env.DLX_BACKEND_TOKEN || "";
const ALLOWED_ORIGINS = new Set(
  String(process.env.DLX_ALLOWED_ORIGINS || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
);
const MAX_REDIRECTS = Number(process.env.DLX_MAX_REDIRECTS || 8);
const MAX_HASH_BYTES = Number(process.env.DLX_MAX_HASH_BYTES || 64 * 1024 * 1024);
const REQUEST_TIMEOUT_MS = Number(process.env.DLX_TIMEOUT_MS || 12000);
const MAX_URL_LENGTH = Number(process.env.DLX_MAX_URL_LENGTH || 4096);
const USER_AGENT = "DownloadLinkXRay/0.1 (+https://localhost)";

function securityHeaders(req) {
  const headers = {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff"
  };
  const origin = req?.headers?.origin || "";
  if (origin && (origin.startsWith("chrome-extension://") || ALLOWED_ORIGINS.has(origin))) {
    headers["access-control-allow-origin"] = origin;
    headers.vary = "Origin";
  }
  return headers;
}

function json(req, res, status, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, {
    ...securityHeaders(req),
    "content-length": Buffer.byteLength(body)
  });
  res.end(body);
}

function parseHttpUrl(rawUrl) {
  if (!rawUrl || String(rawUrl).length > MAX_URL_LENGTH) {
    throw new Error("URL is missing or too long");
  }
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch (_error) {
    throw new Error("Invalid URL");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http:// and https:// URLs are supported");
  }
  if (parsed.username || parsed.password) {
    throw new Error("URLs with embedded credentials are not supported");
  }
  return parsed;
}

function normalizeHostname(hostname) {
  return String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
}

function isPrivateIp(address) {
  if (!address) return true;
  const normalized = normalizeHostname(address);
  const ipVersion = net.isIP(normalized);
  if (ipVersion === 4) {
    const parts = normalized.split(".").map(Number);
    if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) return true;
    const [a, b] = parts;
    return a === 0 ||
      a === 10 ||
      a === 127 ||
      a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19));
  }
  if (ipVersion === 6) {
    const lower = normalized;
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIp(mapped[1]);
    // IPv4-mapped addresses can also be written in hextet form, e.g.
    // ::ffff:7f00:1 is 127.0.0.1. Decode those to the embedded IPv4 too.
    const mappedHex = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (mappedHex) {
      const high = Number.parseInt(mappedHex[1], 16);
      const low = Number.parseInt(mappedHex[2], 16);
      return isPrivateIp(`${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`);
    }
    const firstHextet = Number.parseInt(lower.split(":")[0] || "0", 16);
    return lower === "::1" ||
      lower === "::" ||
      lower.startsWith("64:ff9b:1:") ||
      lower.startsWith("100:") ||
      lower.startsWith("2001:2:") ||
      lower.startsWith("2001:db8:") ||
      lower.startsWith("2002:") ||
      (firstHextet >= 0xfc00 && firstHextet <= 0xfdff) ||
      (firstHextet >= 0xfe80 && firstHextet <= 0xfebf) ||
      (firstHextet >= 0xff00 && firstHextet <= 0xffff);
  }
  return true;
}

async function resolvePublicTarget(rawUrl) {
  const parsed = parseHttpUrl(rawUrl);
  const host = normalizeHostname(parsed.hostname);
  if (host === "localhost" || host.endsWith(".localhost") || host === "local") {
    throw new Error("Localhost targets are blocked");
  }

  const ipVersion = net.isIP(host);
  const addresses = ipVersion
    ? [{ address: host }]
    : await dns.lookup(host, { all: true, verbatim: true });

  if (addresses.length === 0) throw new Error("Host did not resolve");
  const privateAddress = addresses.find((entry) => isPrivateIp(entry.address));
  if (privateAddress) {
    throw new Error(`Private or reserved target blocked: ${privateAddress.address}`);
  }
  return {
    parsed,
    address: addresses[0]
  };
}

async function assertPublicTarget(rawUrl) {
  return (await resolvePublicTarget(rawUrl)).parsed;
}

function withTimeout() {
  if (AbortSignal.timeout) return AbortSignal.timeout(REQUEST_TIMEOUT_MS);
  const controller = new AbortController();
  setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS).unref();
  return controller.signal;
}

async function safeFetch(rawUrl, options = {}) {
  const { parsed, address } = await resolvePublicTarget(rawUrl);
  const transport = parsed.protocol === "https:" ? https : http;
  const method = options.method || "GET";
  const normalizedHost = normalizeHostname(parsed.hostname);
  const requestOptions = {
    protocol: parsed.protocol,
    hostname: normalizedHost,
    port: parsed.port || undefined,
    path: `${parsed.pathname}${parsed.search}`,
    method,
    headers: {
      ...(options.headers || {}),
      host: parsed.host,
      "user-agent": USER_AGENT
    },
    lookup: (_hostname, _lookupOptions, callback) => {
      callback(null, address.address, address.family || net.isIP(address.address));
    },
    servername: normalizedHost,
    timeout: REQUEST_TIMEOUT_MS
  };

  return new Promise((resolve, reject) => {
    const req = transport.request(requestOptions, (res) => {
      const headers = {
        get(name) {
          const value = res.headers[String(name || "").toLowerCase()];
          if (Array.isArray(value)) return value.join(", ");
          return value || null;
        }
      };
      res.cancel = () => {
        res.destroy();
        return Promise.resolve();
      };
      resolve({
        status: res.statusCode || 0,
        ok: (res.statusCode || 0) >= 200 && (res.statusCode || 0) < 300,
        url: parsed.href,
        headers,
        body: res
      });
    });

    req.on("timeout", () => req.destroy(new Error("Request timed out")));
    req.on("error", reject);
    req.end();
  });
}

async function closeBody(response) {
  try {
    await response.body?.cancel?.();
  } catch (_error) {
    // Best-effort cleanup only.
  }
}

async function metadataRequest(rawUrl) {
  let response = await safeFetch(rawUrl, { method: "HEAD" });
  if (response.status === 405 || response.status === 403) {
    await closeBody(response);
    response = await safeFetch(rawUrl, {
      method: "GET",
      headers: { range: "bytes=0-0" }
    });
  }
  return response;
}

async function inspectRedirects(initialUrl) {
  let current = parseHttpUrl(initialUrl).href;
  const redirects = [];
  let response = null;

  for (let index = 0; index <= MAX_REDIRECTS; index += 1) {
    response = await metadataRequest(current);
    const location = response.headers.get("location");
    const isRedirect = response.status >= 300 && response.status < 400 && location;
    if (!isRedirect) break;

    const next = new URL(location, current).href;
    redirects.push({ from: current, to: next, status: response.status });
    await closeBody(response);
    current = next;
  }

  if (redirects.length > MAX_REDIRECTS) {
    throw new Error("Too many redirects");
  }

  const finalUrl = response?.url && response.url !== "about:blank" ? response.url : current;
  return {
    finalUrl,
    status: response?.status || 0,
    redirects,
    contentType: response?.headers.get("content-type") || "",
    contentLength: response?.headers.get("content-length") || "",
    contentDisposition: response?.headers.get("content-disposition") || "",
    headers: response ? {
      "content-type": response.headers.get("content-type") || "",
      "content-length": response.headers.get("content-length") || "",
      "content-disposition": response.headers.get("content-disposition") || ""
    } : {}
  };
}

function filenameFromContentDisposition(contentDisposition) {
  const header = String(contentDisposition || "");
  const encoded = header.match(/filename\*=UTF-8''([^;]+)/i);
  if (encoded) {
    try {
      return decodeURIComponent(encoded[1].replace(/^"|"$/g, ""));
    } catch (_error) {
      return encoded[1].replace(/^"|"$/g, "");
    }
  }

  const plain = header.match(/filename="?([^";]+)"?/i);
  return plain ? plain[1].trim() : "";
}

function looksExecutableFromMetadata(url, contentType, contentDisposition) {
  const dispositionName = filenameFromContentDisposition(contentDisposition);
  if (scoring.hasExecutableExtension(url) || scoring.hasExecutableExtension(dispositionName)) return true;
  return /application\/(x-msdownload|x-msdos-program|x-msi|java-archive|vnd\.android\.package-archive|octet-stream)/i.test(contentType || "");
}

async function sha256RemoteFile(rawUrl, expectedLength) {
  const length = Number(expectedLength || 0);
  if (length > MAX_HASH_BYTES) {
    throw new Error(`File is larger than the ${MAX_HASH_BYTES} byte hashing limit`);
  }

  const response = await safeFetch(rawUrl, { method: "GET" });
  if (!response.ok) {
    await closeBody(response);
    throw new Error(`Cannot download file for hashing: HTTP ${response.status}`);
  }

  const hash = crypto.createHash("sha256");
  let bytes = 0;
  for await (const chunk of response.body) {
    bytes += chunk.length;
    if (bytes > MAX_HASH_BYTES) {
      await closeBody(response);
      throw new Error(`File exceeded the ${MAX_HASH_BYTES} byte hashing limit`);
    }
    hash.update(chunk);
  }

  return {
    sha256: hash.digest("hex"),
    bytes
  };
}

async function virusTotalGet(path) {
  if (!VT_API_KEY) return { skipped: true, reason: "VT_API_KEY is not configured" };
  const response = await fetch(`https://www.virustotal.com/api/v3${path}`, {
    headers: {
      accept: "application/json",
      "x-apikey": VT_API_KEY
    },
    signal: withTimeout()
  });
  const body = await response.json().catch(() => ({}));
  if (response.status === 404) return { notFound: true, status: 404 };
  if (!response.ok) return { error: body.error?.message || `VirusTotal HTTP ${response.status}`, status: response.status };
  return body;
}

async function inspectUrl(rawUrl, deep) {
  const notes = [];
  const metadata = await inspectRedirects(rawUrl);
  const score = scoring.scoreCandidate({ href: metadata.finalUrl, pageUrl: rawUrl });
  const executable = looksExecutableFromMetadata(metadata.finalUrl, metadata.contentType, metadata.contentDisposition) || score.executable;

  const response = {
    ok: true,
    url: rawUrl,
    finalUrl: metadata.finalUrl,
    status: metadata.status,
    redirects: metadata.redirects,
    contentType: metadata.contentType,
    contentLength: metadata.contentLength,
    contentDisposition: metadata.contentDisposition,
    executable,
    score,
    notes
  };

  response.virusTotalUrl = await virusTotalGet(`/urls/${scoring.virusTotalUrlId(metadata.finalUrl)}`);
  if (response.virusTotalUrl?.skipped) notes.push(response.virusTotalUrl.reason);

  if (!deep) return response;
  if (!executable) {
    notes.push("Deep hash check skipped because the target does not look executable.");
    return response;
  }

  const length = Number(metadata.contentLength || 0);
  if (length && length > MAX_HASH_BYTES) {
    notes.push(`Hashing skipped because the target is larger than ${MAX_HASH_BYTES} bytes.`);
    return response;
  }

  const hashResult = await sha256RemoteFile(metadata.finalUrl, metadata.contentLength);
  response.sha256 = hashResult.sha256;
  response.hashedBytes = hashResult.bytes;
  response.virusTotalFile = await virusTotalGet(`/files/${hashResult.sha256}`);
  if (response.virusTotalFile?.skipped) notes.push(response.virusTotalFile.reason);
  return response;
}

async function route(req, res) {
  if (req.method === "OPTIONS") {
    const headers = securityHeaders(req);
    if (headers["access-control-allow-origin"]) {
      headers["access-control-allow-methods"] = "GET, OPTIONS";
      headers["access-control-allow-headers"] = "content-type, x-dlx-client, x-dlx-token";
      res.writeHead(204, headers);
    } else {
      res.writeHead(403, { "x-content-type-options": "nosniff" });
    }
    res.end();
    return;
  }

  const requestUrl = new URL(req.url, `http://${req.headers.host || "127.0.0.1"}`);
  if (requestUrl.pathname === "/health") {
    json(req, res, 200, { ok: true, vtConfigured: Boolean(VT_API_KEY), tokenRequired: Boolean(BACKEND_TOKEN) });
    return;
  }

  if (requestUrl.pathname !== "/inspect") {
    json(req, res, 404, { ok: false, error: "Not found" });
    return;
  }

  if (req.headers["x-dlx-client"] !== "download-link-xray") {
    json(req, res, 403, { ok: false, error: "Missing extension client header" });
    return;
  }

  if (BACKEND_TOKEN && req.headers["x-dlx-token"] !== BACKEND_TOKEN) {
    json(req, res, 401, { ok: false, error: "Invalid backend token" });
    return;
  }

  const target = requestUrl.searchParams.get("url") || "";
  const deep = requestUrl.searchParams.get("deep") === "1";
  try {
    const result = await inspectUrl(target, deep);
    json(req, res, 200, result);
  } catch (error) {
    json(req, res, 400, { ok: false, error: error.message });
  }
}

function start() {
  const server = http.createServer((req, res) => {
    route(req, res).catch((error) => {
      json(req, res, 500, { ok: false, error: error.message });
    });
  });
  server.listen(PORT, "127.0.0.1", () => {
    console.log(`Download Link X-Ray backend listening on http://127.0.0.1:${PORT}`);
    console.log(VT_API_KEY ? "VirusTotal API key configured." : "VT_API_KEY not set; VirusTotal API checks will be skipped.");
  });
  return server;
}

if (require.main === module) {
  start();
}

module.exports = {
  inspectUrl,
  inspectRedirects,
  assertPublicTarget,
  isPrivateIp,
  looksExecutableFromMetadata,
  parseHttpUrl,
  filenameFromContentDisposition,
  resolvePublicTarget,
  scoring,
  start
};
