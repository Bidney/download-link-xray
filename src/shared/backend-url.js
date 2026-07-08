(function exposeBackendUrl(root) {
  "use strict";

  function isLoopbackHostname(hostname) {
    const host = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
    if (host === "localhost" || host === "::1") return true;
    return /^127(?:\.\d{1,3}){0,3}$/.test(host);
  }

  function validateBackendUrl(rawValue, options = {}) {
    const allowEmpty = options.allowEmpty !== false;
    const value = String(rawValue || "").trim().replace(/\/+$/, "");
    if (!value) {
      return allowEmpty
        ? { ok: true, value: "" }
        : { ok: false, error: "Backend URL is required." };
    }

    let parsed;
    try {
      parsed = new URL(value);
    } catch (_error) {
      return { ok: false, error: "Use a valid backend URL." };
    }

    if (parsed.username || parsed.password) {
      return { ok: false, error: "Backend URLs must not contain credentials." };
    }

    if (parsed.protocol === "https:") {
      return { ok: true, value };
    }

    if (parsed.protocol === "http:" && isLoopbackHostname(parsed.hostname)) {
      return { ok: true, value };
    }

    return { ok: false, error: "Use HTTPS for remote backends. HTTP is only allowed for localhost." };
  }

  function backendOriginPattern(rawValue) {
    const validation = validateBackendUrl(rawValue, { allowEmpty: false });
    if (!validation.ok) return "";
    const parsed = new URL(validation.value);
    if (parsed.protocol !== "https:") return "";
    return `${parsed.origin}/*`;
  }

  root.DLXBackendUrl = {
    backendOriginPattern,
    isLoopbackHostname,
    validateBackendUrl
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
