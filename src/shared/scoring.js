(function expose(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  root.DLXScoring = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function buildScoring() {
  "use strict";

  const DOWNLOAD_EXTENSIONS = new Set([
    "7z",
    "apk",
    "bin",
    "bz2",
    "crx",
    "deb",
    "dmg",
    "doc",
    "docx",
    "gz",
    "iso",
    "jar",
    "msi",
    "pdf",
    "pkg",
    "rar",
    "rpm",
    "tar",
    "tgz",
    "torrent",
    "txt",
    "whl",
    "xls",
    "xlsx",
    "zip"
  ]);

  const EXECUTABLE_EXTENSIONS = new Set([
    "apk",
    "appimage",
    "bat",
    "cmd",
    "com",
    "crx",
    "deb",
    "dmg",
    "exe",
    "iso",
    "jar",
    "msi",
    "pkg",
    "ps1",
    "rpm",
    "run",
    "scr",
    "sh",
    "vbs"
  ]);

  const TRUSTED_FILE_HOSTS = [
    "github.com",
    "objects.githubusercontent.com",
    "github-releases.githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    "sourceforge.net",
    "downloads.sourceforge.net",
    "f-droid.org",
    "download.documentfoundation.org",
    "cdn.kernel.org",
    "nodejs.org",
    "python.org",
    "microsoft.com",
    "download.microsoft.com"
  ];

  const AD_OR_REDIRECT_HOST_PATTERNS = [
    "adf.ly",
    "ads",
    "adserver",
    "adservice",
    "adsterra",
    "doubleclick.net",
    "googlesyndication.com",
    "linkbucks",
    "mgid.com",
    "ouo.io",
    "outbrain.com",
    "popads",
    "propellerads",
    "shorte.st",
    "taboola.com",
    "traffic",
    "trk",
    "yads"
  ];

  const DOWNLOAD_WORDS = [
    "download",
    "download now",
    "direct download",
    "get file",
    "mirror",
    "installer",
    "setup",
    "pobierz",
    "pobieranie",
    "ściągnij",
    "sciagnij",
    "descargar",
    "telecharger",
    "herunterladen",
    "latest version",
    "windows",
    "macos",
    "linux",
    "android"
  ];

  const FAKE_OR_AD_WORDS = [
    "advertisement",
    "advertiser",
    "sponsor",
    "sponsored",
    "recommended offer",
    "continue to site",
    "download manager",
    "driver update",
    "flash player",
    "scan now",
    "fix now",
    "you won",
    "start now",
    "play now"
  ];

  const TRACKING_PARAMS = [
    "adid",
    "aff",
    "affiliate",
    "campaign",
    "clickid",
    "gclid",
    "msclkid",
    "ref",
    "subid",
    "utm_campaign",
    "utm_medium",
    "utm_source"
  ];

  function normalizeUrl(rawUrl, baseUrl) {
    if (!rawUrl || typeof rawUrl !== "string") return null;
    const trimmed = rawUrl.trim();
    if (!trimmed || trimmed === "#") return null;
    try {
      return new URL(trimmed, baseUrl || undefined);
    } catch (_error) {
      return null;
    }
  }

  function extensionFromPath(pathname) {
    const clean = String(pathname || "").split("/").pop() || "";
    const withoutTrailing = clean.replace(/[?#].*$/, "");
    const match = withoutTrailing.match(/\.([a-z0-9]{1,12})$/i);
    return match ? match[1].toLowerCase() : "";
  }

  function filenameFromUrl(url) {
    try {
      const parsed = typeof url === "string" ? new URL(url) : url;
      const last = decodeURIComponent(parsed.pathname.split("/").pop() || "");
      return last || "";
    } catch (_error) {
      return "";
    }
  }

  function hostContains(hostname, fragments) {
    const host = String(hostname || "").toLowerCase();
    return fragments.some((fragment) => host.includes(fragment));
  }

  function textIncludes(text, phrases) {
    const normalized = String(text || "").toLowerCase().replace(/\s+/g, " ").trim();
    return phrases.some((phrase) => normalized.includes(phrase));
  }

  function hasSuspiciousDoubleExtension(filename) {
    return /\.(pdf|jpg|jpeg|png|gif|txt|doc|docx|xls|xlsx)\.(exe|scr|bat|cmd|ps1|vbs|jar)$/i.test(filename || "");
  }

  function hasExecutableExtension(pathOrFilename) {
    const ext = extensionFromPath(pathOrFilename || "");
    return EXECUTABLE_EXTENSIONS.has(ext);
  }

  function looksLikeDownloadExtension(pathOrFilename) {
    const ext = extensionFromPath(pathOrFilename || "");
    return DOWNLOAD_EXTENSIONS.has(ext) || EXECUTABLE_EXTENSIONS.has(ext);
  }

  function scoreCandidate(candidate) {
    const reasons = [];
    const warnings = [];
    let score = 0;

    const pageUrl = candidate.pageUrl || "";
    const parsed = normalizeUrl(candidate.href, pageUrl);
    const label = [candidate.label, candidate.ariaLabel, candidate.title, candidate.alt]
      .filter(Boolean)
      .join(" ");
    const lowerHref = String(candidate.href || "").toLowerCase();

    if (!parsed) {
      score -= 35;
      warnings.push("No verifiable link target");
      return finalize(candidate, null, score, reasons, warnings);
    }

    if (!/^https?:$/.test(parsed.protocol)) {
      score -= 45;
      warnings.push(`Non-web URL scheme: ${parsed.protocol.replace(":", "")}`);
    }

    const fileName = filenameFromUrl(parsed);
    const ext = extensionFromPath(parsed.pathname);
    const isDownloadExt = DOWNLOAD_EXTENSIONS.has(ext) || EXECUTABLE_EXTENSIONS.has(ext);
    const isExecutable = EXECUTABLE_EXTENSIONS.has(ext);

    if (isDownloadExt) {
      score += 42;
      reasons.push(`URL ends in .${ext}`);
    }

    if (isExecutable) {
      score += 4;
      warnings.push(`Executable-style file type: .${ext}`);
    }

    if (candidate.downloadAttr) {
      score += 30;
      reasons.push("Uses the browser download attribute");
    }

    if (textIncludes(label, DOWNLOAD_WORDS)) {
      score += 14;
      reasons.push("Download wording is visible");
    }

    if (textIncludes(label, FAKE_OR_AD_WORDS)) {
      score -= 35;
      warnings.push("Ad-like or misleading wording");
    }

    if (hostContains(parsed.hostname, TRUSTED_FILE_HOSTS)) {
      score += 14;
      reasons.push("Known software/file host");
    }

    if (hostContains(parsed.hostname, AD_OR_REDIRECT_HOST_PATTERNS)) {
      score -= 55;
      warnings.push("Known ad or redirect-style host");
    }

    if (/^(javascript|data|blob):/i.test(lowerHref)) {
      score -= 40;
      warnings.push("Target is not a normal HTTP link");
    }

    if (hasSuspiciousDoubleExtension(fileName)) {
      score -= 45;
      warnings.push("Suspicious double extension");
    }

    const pageHost = normalizeUrl(pageUrl)?.hostname || "";
    if (pageHost && parsed.hostname && parsed.hostname !== pageHost) {
      score -= 5;
      reasons.push(`Leaves ${pageHost}`);
    } else if (pageHost && parsed.hostname === pageHost) {
      score += 6;
      reasons.push("Same-site link");
    }

    const trackingParams = [...parsed.searchParams.keys()].filter((key) =>
      TRACKING_PARAMS.includes(key.toLowerCase())
    );
    if (trackingParams.length > 0) {
      score -= Math.min(14, trackingParams.length * 4);
      warnings.push(`Tracking parameters: ${trackingParams.slice(0, 3).join(", ")}`);
    }

    if (candidate.area && candidate.area > 90000 && !isDownloadExt) {
      score -= 10;
      warnings.push("Very large button without a file-looking URL");
    }

    if (/\/(redirect|out|go|visit|click|track)\b/i.test(parsed.pathname)) {
      score -= 15;
      warnings.push("Redirect-style path");
    }

    return finalize(candidate, parsed, score, reasons, warnings);
  }

  function finalize(candidate, parsedUrl, score, reasons, warnings) {
    const href = parsedUrl ? parsedUrl.href : candidate.href || "";
    const fileName = parsedUrl ? filenameFromUrl(parsedUrl) : "";
    const ext = parsedUrl ? extensionFromPath(parsedUrl.pathname) : "";
    const executable = EXECUTABLE_EXTENSIONS.has(ext) || hasSuspiciousDoubleExtension(fileName);

    let verdict = "unknown";
    if (score >= 44) verdict = "likely-real";
    if (score <= -15) verdict = "suspicious";
    if (executable && score >= 20) verdict = "executable";

    let confidence = "low";
    if (Math.abs(score) >= 35) confidence = "medium";
    if (Math.abs(score) >= 60) confidence = "high";

    return {
      href,
      score,
      verdict,
      confidence,
      executable,
      fileName,
      extension: ext,
      host: parsedUrl ? parsedUrl.hostname : "",
      reasons,
      warnings
    };
  }

  function summarizeCandidates(candidates) {
    const scored = candidates.map(scoreCandidate).sort((a, b) => b.score - a.score);
    const best = scored.find((item) => item.score >= 25) || null;
    const suspicious = scored.filter((item) => item.verdict === "suspicious").length;
    const executables = scored.filter((item) => item.executable).length;
    return {
      total: scored.length,
      suspicious,
      executables,
      best,
      scored
    };
  }

  function virusTotalUrlId(url) {
    const value = typeof Buffer !== "undefined"
      ? Buffer.from(url).toString("base64")
      : btoa(url);
    return value.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  return {
    DOWNLOAD_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    scoreCandidate,
    summarizeCandidates,
    normalizeUrl,
    extensionFromPath,
    filenameFromUrl,
    hasExecutableExtension,
    looksLikeDownloadExtension,
    hasSuspiciousDoubleExtension,
    virusTotalUrlId
  };
});
