import test from "node:test";
import assert from "node:assert/strict";
import { parseDownloadItem } from "../modules/downloadParser.js";

test("parseDownloadItem parses executable download item", () => {
  const item = {
    id: 101,
    url: "https://example.com/downloads/setup.exe",
    filename: "C:\\Users\\User\\Downloads\\setup.exe",
    mime: "application/x-msdownload",
    totalBytes: 52428800,
    danger: "safe",
    state: "in_progress"
  };

  const parsed = parseDownloadItem(item);
  assert.equal(parsed.downloadId, 101);
  assert.equal(parsed.filename, "setup.exe");
  assert.equal(parsed.extension, "exe");
  assert.equal(parsed.category, "executable");
  assert.equal(parsed.isExecutable, true);
  assert.equal(parsed.domain, "example.com");
  assert.equal(parsed.isHttps, true);
});

test("parseDownloadItem handles missing filename by extracting from URL", () => {
  const item = {
    id: 102,
    url: "https://files.python.org/packages/python-3.11.0.tar.gz",
    totalBytes: 25000000
  };

  const parsed = parseDownloadItem(item);
  assert.equal(parsed.filename, "python-3.11.0.tar.gz");
  assert.equal(parsed.extension, "gz");
  assert.equal(parsed.category, "archive");
});
