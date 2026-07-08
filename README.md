# Download Link X-Ray

Chrome MV3 extension that highlights likely real download links, flags likely fake/ad links, and opens a right-click inspection panel for executable-style targets.

## What works now

- Page overlay for likely real download links.
- Red badges for likely ad/redirect traps.
- Orange badges for executable-style files such as `.exe`, `.msi`, `.dmg`, `.apk`, `.jar`, `.ps1`.
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

Then open the extension options page and set:

```text
http://127.0.0.1:8787
```

## Test

```bash
npm test
```

## Current limitations

- The highlighter uses heuristics, not certainty.
- The backend does not bypass captchas, timers, login walls, paywalls, or JavaScript-generated protected links.
- Deep checks do hash lookup only. It does not auto-upload binaries to VirusTotal.
- Hashing is capped at 64 MB by default. Change with `DLX_MAX_HASH_BYTES`.
