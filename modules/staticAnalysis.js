// modules/staticAnalysis.js
// Module 5b: Local Static File Analysis.
// Runs entirely client-side against the ArrayBuffer that fileIntegrity.js
// already fetched for hashing — no extra network cost. This is the
// "actually look at the bytes" layer: catches extension spoofing, packed/
// encrypted payloads, embedded macros, and download-and-execute script
// patterns that a hash-only check would never see.
//
// Deliberately NOT a signature-based antivirus engine — that's not
// achievable in JS against arbitrary binaries, and pretending otherwise
// would be dishonest about what this can catch. This is a set of concrete,
// verifiable structural checks.

import {
  FILE_SIGNATURES,
  SUSPICIOUS_SCRIPT_PATTERNS,
  HIGH_ENTROPY_THRESHOLD,
  STATIC_ANALYSIS_MAX_BYTES
} from "./config.js";

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function detectFileType(buffer) {
  const head = new Uint8Array(buffer.slice(0, 16));
  const headHex = bytesToHex(head);
  for (const sig of FILE_SIGNATURES) {
    if (headHex.startsWith(sig.hex)) return sig;
  }
  return null;
}

function shannonEntropy(bytes) {
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
  let entropy = 0;
  const len = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue;
    const p = counts[i] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Zip-based container formats (docx/xlsx/pptx/jar/apk all start with PK..)
// carry an internal file listing we can peek at without a full unzip
// implementation: local file headers each start with the same PK\x03\x04
// signature followed by a filename. Cheap substring scan is good enough to
// flag "this document contains a macro project" or "this archive contains
// an executable" without needing a zip library.
function scanZipEntryNames(buffer) {
  const bytes = new Uint8Array(buffer);
  const text = Array.from(bytes.subarray(0, Math.min(bytes.length, STATIC_ANALYSIS_MAX_BYTES)))
    .map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : " "))
    .join("");

  const findings = [];
  if (/vbaProject\.bin/i.test(text)) {
    findings.push({ key: "EMBEDDED_MACRO", label: "Contains a VBA macro project (vbaProject.bin)" });
  }
  const exeInsideArchiveMatch = text.match(/[^\s"'<>]{1,80}\.(exe|scr|bat|cmd|ps1|vbs)\b/i);
  if (exeInsideArchiveMatch) {
    findings.push({ key: "EXECUTABLE_IN_ARCHIVE", label: `Archive contains an executable entry (${exeInsideArchiveMatch[0]})` });
  }
  return findings;
}

function scanScriptText(buffer) {
  const bytes = new Uint8Array(buffer.slice(0, STATIC_ANALYSIS_MAX_BYTES));
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const findings = [];
  for (const pattern of SUSPICIOUS_SCRIPT_PATTERNS) {
    if (pattern.rx.test(text)) {
      findings.push({ key: pattern.key, label: pattern.label });
    }
  }
  return findings;
}

/**
 * @param {ArrayBuffer} buffer - the full downloaded file content
 * @param {{extension: string, category: string}} parsed
 */
export function runStaticAnalysis(buffer, parsed) {
  if (!buffer || buffer.byteLength === 0) {
    return { staticAnalysisScore: 55, status: "no_content", findings: [] };
  }

  const findings = [];
  const detected = detectFileType(buffer);

  // 1. Extension spoofing: the actual bytes don't match what the extension claims.
  if (detected && !detected.categories.includes(parsed.category) && parsed.category !== "other") {
    findings.push({
      key: "EXTENSION_MISMATCH",
      severity: "critical",
      label: `File claims to be .${parsed.extension} (${parsed.category}) but its content signature is ${detected.type}`
    });
  }

  // 2. Entropy — only meaningful for formats that should be structured/plain,
  // not already-compressed formats (archives, media) where high entropy is normal.
  const entropyRelevant = ["executable", "script", "code", "document"].includes(parsed.category);
  if (entropyRelevant) {
    const sampleBytes = new Uint8Array(buffer.slice(0, Math.min(buffer.byteLength, STATIC_ANALYSIS_MAX_BYTES)));
    const entropy = shannonEntropy(sampleBytes);
    if (entropy >= HIGH_ENTROPY_THRESHOLD) {
      findings.push({
        key: "HIGH_ENTROPY",
        severity: "warning",
        label: `Unusually high byte-entropy (${entropy.toFixed(2)}/8.0) for a .${parsed.extension} file — consistent with packing/encryption/obfuscation`
      });
    }
  }

  // 3. Zip-based containers (docx/xlsx/pptx/jar/apk/zip) — macro & embedded-executable check.
  if (detected?.type === "zip_based") {
    for (const f of scanZipEntryNames(buffer)) {
      findings.push({ key: f.key, severity: "warning", label: f.label });
    }
  }

  // 4. Script content pattern scan.
  if (["script"].includes(parsed.category) || ["js", "ps1", "vbs", "bat", "cmd", "sh"].includes(parsed.extension)) {
    for (const f of scanScriptText(buffer)) {
      findings.push({ key: f.key, severity: "critical", label: f.label });
    }
  }

  const hasCritical = findings.some(f => f.severity === "critical");
  const hasWarning = findings.some(f => f.severity === "warning");

  let staticAnalysisScore = 95;
  if (hasCritical) staticAnalysisScore = 5;
  else if (hasWarning) staticAnalysisScore = 45;

  return {
    staticAnalysisScore,
    status: findings.length ? "findings" : "clean",
    detectedType: detected?.type || "unknown",
    findings
  };
}
