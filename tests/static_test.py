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
    assert manifest["host_permissions"] == ["http://*/*", "https://*/*"]


def test_context_menu_and_backend_flow_exist():
    worker = read_text("src/background/service-worker.js")
    inspector = read_text("src/ui/inspect.js")
    backend = read_text("backend/server.js")

    assert "Inspect download link" in worker
    assert "Check executable risk" in worker
    assert "dlxBackendUrl" in inspector
    assert "/inspect" in inspector
    assert "VT_API_KEY" in backend
    assert "/files/" in backend
    assert "/urls/" in backend


def test_no_embedded_virustotal_key():
    key_pattern = re.compile(r"x-apikey\s*:\s*['\"][a-z0-9]{20,}", re.IGNORECASE)
    for path in ROOT.rglob("*"):
      if path.is_file() and path.suffix in {".js", ".json", ".html", ".md"}:
        assert not key_pattern.search(path.read_text(encoding="utf-8")), path


def test_backend_has_ssrf_controls():
    backend = read_text("backend/server.js")
    for expected in [
        "localhost",
        "127",
        "192.168",
        "172",
        "10",
        "dns.lookup",
        "redirect: \"manual\"",
        "MAX_REDIRECTS",
        "MAX_HASH_BYTES",
    ]:
      assert expected in backend


if __name__ == "__main__":
    tests = [
        test_manifest_references_existing_files,
        test_permissions_are_expected_for_mvp,
        test_context_menu_and_backend_flow_exist,
        test_no_embedded_virustotal_key,
        test_backend_has_ssrf_controls,
    ]
    for test in tests:
      test()
      print(f"ok - {test.__name__}")
