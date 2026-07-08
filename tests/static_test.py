#!/usr/bin/env python3
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_text(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def test_manifest_references_existing_files():
    manifest = json.loads(read_text("manifest.json"))
    assert manifest["manifest_version"] == 3
    assert manifest["background"]["service_worker"] == "src/background/service-worker.js"
    assert (ROOT / manifest["background"]["service_worker"]).exists()
    assert (ROOT / manifest["action"]["default_popup"]).exists()
    assert (ROOT / manifest["options_page"]).exists()

    content_script = manifest["content_scripts"][0]
    assert content_script["js"][0] == "src/shared/scoring.js"
    for script in content_script["js"]:
      assert (ROOT / script).exists(), script
    for stylesheet in content_script["css"]:
      assert (ROOT / stylesheet).exists(), stylesheet


def test_permissions_are_expected_for_mvp():
    manifest = json.loads(read_text("manifest.json"))
    assert set(manifest["permissions"]) == {"activeTab", "contextMenus", "storage"}
    assert "http://*/*" not in manifest["host_permissions"]
    assert "https://*/*" not in manifest["host_permissions"]
    assert set(manifest["host_permissions"]) == {"http://127.0.0.1/*", "http://localhost/*"}
    assert manifest["optional_host_permissions"] == ["https://*/*"]
    csp = manifest["content_security_policy"]["extension_pages"]
    assert "script-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "connect-src" in csp


def test_context_menu_and_backend_flow_exist():
    worker = read_text("src/background/service-worker.js")
    inspector = read_text("src/ui/inspect.js")
    backend = read_text("backend/server.js")

    assert "Inspect download link" in worker
    assert "Check executable risk" in worker
    assert "dlxBackendUrl" in inspector
    assert "/inspect" in inspector
    assert "chrome.permissions.contains" in inspector
    assert "chrome.permissions.request" in read_text("src/ui/options.js")
    assert "VT_API_KEY" in backend
    assert "DLX_BACKEND_TOKEN" in backend
    assert "x-dlx-client" in inspector
    assert "x-dlx-token" in inspector
    assert "Missing extension client header" in backend
    assert "/files/" in backend
    assert "/urls/" in backend


def test_popup_exposes_global_and_site_toggles():
    popup_html = read_text("src/ui/popup.html")
    popup_js = read_text("src/ui/popup.js")
    content_js = read_text("src/content/content.js")

    assert 'id="enabled"' in popup_html
    assert 'id="siteEnabled"' in popup_html
    assert "dlxSiteDisabled" in popup_js
    assert "hostnameFromTab" in popup_js
    assert "dlxSiteDisabled" in content_js
    assert "site-disabled" in content_js


def test_no_embedded_virustotal_key():
    key_pattern = re.compile(r"x-apikey\s*:\s*['\"][a-z0-9]{20,}", re.IGNORECASE)
    for path in ROOT.rglob("*"):
      if path.is_file() and path.suffix in {".js", ".json", ".html", ".md"}:
        assert not key_pattern.search(path.read_text(encoding="utf-8")), path


def test_no_runtime_html_injection_or_wildcard_cors():
    runtime_files = [
        "src/ui/inspect.js",
        "src/ui/options.js",
        "src/ui/popup.js",
        "src/content/content.js",
        "src/background/service-worker.js",
    ]
    for relative in runtime_files:
      text = read_text(relative)
      assert "innerHTML" not in text, relative
      assert "insertAdjacentHTML" not in text, relative
      assert "document.write" not in text, relative
      assert "eval(" not in text, relative
      assert "new Function" not in text, relative

    backend = read_text("backend/server.js")
    assert '"access-control-allow-origin": "*"' not in backend
    assert "origin.startsWith(\"chrome-extension://\")" in backend


def test_backend_has_ssrf_controls():
    backend = read_text("backend/server.js")
    for expected in [
        "localhost",
        "127",
        "a === 192 && b === 168",
        "172",
        "10",
        "dns.lookup",
        "lookup:",
        "MAX_REDIRECTS",
        "MAX_HASH_BYTES",
        "MAX_URL_LENGTH",
        "URLs with embedded credentials",
    ]:
      assert expected in backend


if __name__ == "__main__":
    tests = [
        test_manifest_references_existing_files,
        test_permissions_are_expected_for_mvp,
        test_context_menu_and_backend_flow_exist,
        test_popup_exposes_global_and_site_toggles,
        test_no_embedded_virustotal_key,
        test_no_runtime_html_injection_or_wildcard_cors,
        test_backend_has_ssrf_controls,
    ]
    for test in tests:
      test()
      print(f"ok - {test.__name__}")
