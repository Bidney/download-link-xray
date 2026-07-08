"use strict";

const assert = require("assert");
const test = require("node:test");
const backend = require("../backend/server");

test("blocks private IPv4 ranges", () => {
  assert.equal(backend.isPrivateIp("127.0.0.1"), true);
  assert.equal(backend.isPrivateIp("10.0.0.7"), true);
  assert.equal(backend.isPrivateIp("192.168.1.2"), true);
  assert.equal(backend.isPrivateIp("172.16.0.5"), true);
  assert.equal(backend.isPrivateIp("8.8.8.8"), false);
});

test("blocks private and reserved IPv6 ranges", () => {
  assert.equal(backend.isPrivateIp("::1"), true);
  assert.equal(backend.isPrivateIp("::"), true);
  assert.equal(backend.isPrivateIp("fc00::1"), true);
  assert.equal(backend.isPrivateIp("fd12::1"), true);
  assert.equal(backend.isPrivateIp("fe80::1"), true);
  assert.equal(backend.isPrivateIp("ff02::1"), true);
  assert.equal(backend.isPrivateIp("::ffff:192.168.0.1"), true);
  assert.equal(backend.isPrivateIp("2606:4700:4700::1111"), false);
});

test("blocks localhost hostnames before fetch", () => {
  assert.throws(() => backend.parseHttpUrl("file:///etc/passwd"), /Only http/);
  assert.throws(() => backend.parseHttpUrl("https://user:pass@example.com/file.exe"), /credentials/);
});

test("recognizes executable metadata", () => {
  assert.equal(backend.looksExecutableFromMetadata("https://example.com/setup.exe", "", ""), true);
  assert.equal(backend.looksExecutableFromMetadata("https://example.com/download", "", "attachment; filename=\"setup.exe\""), true);
  assert.equal(backend.looksExecutableFromMetadata("https://example.com/file", "application/x-msdownload", ""), true);
  assert.equal(backend.looksExecutableFromMetadata("https://example.com/readme.txt", "text/plain", ""), false);
});
