import test from "node:test";
import assert from "node:assert/strict";
import { checkFileIntegrity } from "../modules/fileIntegrity.js";

test("checkFileIntegrity returns fetch_failed when server returns non-200", async () => {
  // Mock global fetch for testing
  const originalFetch = global.fetch;
  global.fetch = async () => ({ ok: false, status: 404 });

  try {
    const result = await checkFileIntegrity("https://example.com/nonexistent.bin", {}, "nonexistent.bin");
    assert.equal(result.status, "fetch_failed");
    assert.equal(result.integrityScore, 50);
  } finally {
    global.fetch = originalFetch;
  }
});

test("checkFileIntegrity skips files exceeding maximum byte cap", async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => ({
    ok: true,
    headers: new Map([["content-length", "300000000"]])
  });

  try {
    const result = await checkFileIntegrity("https://example.com/huge-file.iso", {}, "huge-file.iso");
    assert.equal(result.status, "skipped_too_large");
    assert.equal(result.integrityScore, 60);
  } finally {
    global.fetch = originalFetch;
  }
});
