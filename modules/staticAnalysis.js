// modules/staticAnalysis.js
// Module 5b: Local Static File Analysis.

import {
  FILE_SIGNATURES,
  SUSPICIOUS_SCRIPT_PATTERNS,
  HIGH_ENTROPY_THRESHOLD,
  STATIC_ANALYSIS_MAX_BYTES
} from "./config.js";

// Standard EICAR anti-malware test signature pattern
const EICAR_STANDARD_PATTERN = /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/i;

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

function scanZipEntryNames(buffer) {
  const bytes = new Uint8Array(buffer);
  const text = Array.from(bytes.subarray(0, Math.min(bytes.length, STATIC_ANALYSIS_MAX_BYTES)))
    .map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : " "))
    .join("");

  const findings = [];
  if (/vbaProject\.bin/i.test(text)) {
    findings.push({ key: "EMBEDDED_MACRO", label: "Contains a VBA macro project (vbaProject.bin)" });
  }

  const exeInsideArchiveMatch = text.match(/[^\s"'<>]{1,80}\.(exe|scr|bat|cmd|ps1|vbs|com|pif)\b/i);
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

export function runStaticAnalysis(buffer, parsed) {
  if (!buffer || buffer.byteLength === 0) {
    return { staticAnalysisScore: 55, status: "no_content", findings: [], reason: "Empty file buffer" };
  }

  const findings = [];
  const sampleBytes = new Uint8Array(buffer.slice(0, Math.min(buffer.byteLength, STATIC_ANALYSIS_MAX_BYTES)));
  const textSample = new TextDecoder("latin1").decode(sampleBytes);

  // 1. EICAR Antivirus Test Pattern Detection
  if (EICAR_STANDARD_PATTERN.test(textSample)) {
    findings.push({
      key: "EICAR_MALWARE_TEST_PATTERN",
      severity: "critical",
      label: "Standard EICAR Anti-Malware Test Signature Detected"
    });
  }

  // 2. Extension spoofing check
  const detected = detectFileType(buffer);
  if (detected && !detected.categories.includes(parsed.category) && parsed.category !== "other") {
    findings.push({
      key: "EXTENSION_MISMATCH",
      severity: "critical",
      label: `File claims to be .${parsed.extension} (${parsed.category}) but signature is ${detected.type}`
    });
  }

  // 3. Shannon Entropy check
  const entropyRelevant = ["executable", "script", "code", "document"].includes(parsed.category);
  if (entropyRelevant) {
    const entropy = shannonEntropy(sampleBytes);
    if (entropy >= HIGH_ENTROPY_THRESHOLD) {
      findings.push({
        key: "HIGH_ENTROPY",
        severity: "warning",
        label: `High byte-entropy (${entropy.toFixed(2)}/8.0) — possible packed/encrypted content`
      });
    }
  }

  // 4. Archive inspection
  if (detected?.type === "zip_based" || parsed.category === "archive") {
    for (const f of scanZipEntryNames(buffer)) {
      const isCritical = f.key === "EXECUTABLE_IN_ARCHIVE" && ["zip", "rar", "7z"].includes(parsed.extension);
      findings.push({ key: f.key, severity: isCritical ? "critical" : "warning", label: f.label });
    }
  }

  // 5. Script pattern scan
  if (["script"].includes(parsed.category) || ["js", "ps1", "vbs", "bat", "cmd", "sh"].includes(parsed.extension)) {
    for (const f of scanScriptText(buffer)) {
      findings.push({ key: f.key, severity: "critical", label: f.label });
    }
  }

  const hasCritical = findings.some(f => f.severity === "critical");
  const hasWarning = findings.some(f => f.severity === "warning");

  let staticAnalysisScore = 95;
  if (hasCritical) staticAnalysisScore = 0;
  else if (hasWarning) staticAnalysisScore = 45;

  return {
    staticAnalysisScore,
    status: findings.length ? "findings" : "clean",
    detectedType: detected?.type || "unknown",
    findings,
    reason: hasCritical
      ? findings.find(f => f.severity === "critical")?.label
      : hasWarning
      ? findings.find(f => f.severity === "warning")?.label
      : "Passed static signatures and structural checks"
  };
}