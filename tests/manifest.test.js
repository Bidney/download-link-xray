"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const test = require("node:test");

const root = path.resolve(__dirname, "..");

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
}

test("manifest is valid MV3 and references existing files", () => {
  const manifest = readJson("manifest.json");
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.background.service_worker, "src/background/service-worker.js");
  assert.ok(fs.existsSync(path.join(root, manifest.background.service_worker)));
  assert.ok(fs.existsSync(path.join(root, manifest.action.default_popup)));
  assert.ok(fs.existsSync(path.join(root, manifest.options_page)));

  for (const script of manifest.content_scripts[0].js) {
    assert.ok(fs.existsSync(path.join(root, script)), `${script} should exist`);
  }
  for (const css of manifest.content_scripts[0].css) {
    assert.ok(fs.existsSync(path.join(root, css)), `${css} should exist`);
  }
});

test("extension does not hardcode reputation API keys", () => {
  const files = [
    "manifest.json",
    "src/background/service-worker.js",
    "src/content/content.js",
    "src/ui/inspect.js",
    "backend/server.js"
  ];

  for (const file of files) {
    const text = fs.readFileSync(path.join(root, file), "utf8");
    assert.doesNotMatch(text, /x-apikey\s*:\s*["'][a-z0-9]{20,}/i);
  }
});
