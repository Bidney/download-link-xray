# Download Link X-Ray

Chrome MV3 extension that highlights likely real download links, flags likely fake/ad links, and opens a right-click inspection panel for executable-style targets.

## What works now

- Page overlay for likely real download links.
- Red badges for likely ad/redirect traps.
- Orange badges for executable-style files such as `.exe`, `.msi`, `.dmg`, `.apk`, `.jar`, `.ps1`.
- Pinned extension popup controls:
  - global on/off
  - current-site on/off
  - rescan current page
- Right-click menu on links:
  - `Inspect download link`
  - `Check executable risk`
- Optional backend:
  - follows redirects with SSRF protections
  - reads response headers
  - checks VirusTotal URL reputation when `VT_API_KEY` is configured
  - hashes executable-looking files up to 64 MB
  - checks VirusTotal file-hash reputation

The extension never stores a VirusTotal API key. Keep reputation API keys in the backend.

## Load in Chrome

1. Open `chrome://extensions`.
2. Enable `Developer mode`.
3. Click `Load unpacked`.
4. Select this directory: `download-link-xray`.

## Run the optional backend

Requires Node.js 18 or newer. Without a VirusTotal key:

```bash
node backend/server.js
```

With VirusTotal:

```bash
VT_API_KEY=your_key_here node backend/server.js
```

With an optional backend token for a hosted/shared backend:

```bash
DLX_BACKEND_TOKEN=change_me VT_API_KEY=your_key_here node backend/server.js
```

Then open the extension options page and set:

```text
http://127.0.0.1:8787
```

For a remote backend, use HTTPS and set the same backend token in the extension options page.
When you save a remote backend URL, Chrome will ask for host permission for that backend origin only.
The backend does not enable wildcard CORS by default; set `DLX_ALLOWED_ORIGINS` only if you intentionally need browser-origin access outside the extension.

## Test

```bash
npm test
```

## Current limitations

- The highlighter uses heuristics, not certainty.
- The backend does not bypass captchas, timers, login walls, paywalls, or JavaScript-generated protected links.
- Deep checks do hash lookup only. It does not auto-upload binaries to VirusTotal.
- Hashing is capped at 64 MB by default. Change with `DLX_MAX_HASH_BYTES`.
- The backend blocks private/reserved targets and pins DNS resolution during checks, but a public deployment should still sit behind normal rate limiting.
