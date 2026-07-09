"use strict";

const assert = require("assert");
const test = require("node:test");
const scoring = require("../src/shared/scoring");

test("scores direct software downloads as likely real", () => {
  const result = scoring.scoreCandidate({
    href: "https://github.com/acme/tool/releases/download/v1.2.3/tool-setup.exe",
    label: "Download Windows installer",
    pageUrl: "https://github.com/acme/tool"
  });

  assert.equal(result.executable, true);
  assert.equal(result.verdict, "executable");
  assert.ok(result.score >= 60);
});

test("marks ad network links as suspicious", () => {
  const result = scoring.scoreCandidate({
    href: "https://adservice.example.com/redirect?aff=abc&subid=123",
    label: "Download now",
    pageUrl: "https://example-download-site.test/file"
  });

  assert.equal(result.verdict, "suspicious");
  assert.ok(result.score < 0);
});

test("detects suspicious double extensions", () => {
  const result = scoring.scoreCandidate({
    href: "https://files.example.com/invoice.pdf.exe",
    label: "Download invoice",
    pageUrl: "https://files.example.com"
  });

  assert.equal(result.executable, true);
  assert.ok(result.warnings.some((warning) => warning.includes("double extension")));
});

test("understands Polish download wording", () => {
  const result = scoring.scoreCandidate({
    href: "https://example.pl/pliki/program.zip",
    label: "Pobierz program",
    pageUrl: "https://example.pl"
  });

  assert.ok(result.score >= 50);
  assert.notEqual(result.verdict, "suspicious");
});

test("does not flag download hosts as ad hosts by substring", () => {
  const result = scoring.scoreCandidate({
    href: "https://downloads.sourceforge.net/project/tool/tool-setup.zip",
    label: "Download",
    pageUrl: "https://sourceforge.net/projects/tool"
  });

  assert.ok(result.reasons.some((reason) => reason.includes("Known software/file host")));
  assert.ok(!result.warnings.some((warning) => warning.includes("ad or redirect")));
  assert.notEqual(result.verdict, "suspicious");
});

test("does not trust look-alike hosts that merely contain a trusted domain", () => {
  const result = scoring.scoreCandidate({
    href: "https://github.com.evil.example/tool/tool-setup.exe",
    label: "Download",
    pageUrl: "https://github.com.evil.example"
  });

  assert.ok(!result.reasons.some((reason) => reason.includes("Known software/file host")));
});

test("VirusTotal URL IDs are base64url without padding", () => {
  const id = scoring.virusTotalUrlId("https://example.com/download/file.exe");
  assert.doesNotMatch(id, /[+/=]/);
  assert.ok(id.length > 10);
});
