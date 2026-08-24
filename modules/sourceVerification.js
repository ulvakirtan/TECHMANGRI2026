// modules/sourceVerification.js
// Module 3: Source Verification & Website Vulnerability Engine.

import { KNOWN_PUBLISHERS, VULNERABILITY_DEFINITIONS } from "./config.js";

const SUSPICIOUS_TLDS = new Set(["top", "xyz", "cc", "click", "download", "link", "gq", "work", "cf", "tk", "ml", "ga"]);
const MULTIPART_TLDS = new Set(["co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "edu.au", "co.nz", "co.jp", "com.br"]);
const levenshteinCache = new Map();

export function levenshtein(a, b) {
  if (a === b) return 0;
  const lenDiff = Math.abs(a.length - b.length);
  if (lenDiff > 2) return lenDiff;
  const key = a < b ? `${a}:${b}` : `${b}:${a}`;
  if (levenshteinCache.has(key)) return levenshteinCache.get(key);

  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array(b.length + 1).fill(0).map((_, j) => (i === 0 ? j : 0))
  );

  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }

  const result = dp[a.length][b.length];
  if (levenshteinCache.size < 5000) {
    levenshteinCache.set(key, result);
  }
  return result;
}

export function registrableDomain(hostname) {
  if (!hostname) return "";
  const parts = hostname.toLowerCase().split(".");
  if (parts.length <= 2) return hostname;
  
  const lastTwo = parts.slice(-2).join(".");
  if (MULTIPART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

export function verifySource(domain, extraTrustedDomains = []) {
  const reg = registrableDomain(domain);
  const trustedList = [
    ...KNOWN_PUBLISHERS.flatMap(p => p.domains),
    ...extraTrustedDomains
  ];

  const isKnownOfficial = trustedList.some(d => reg === d || domain === d || domain.endsWith(`.${d}`));

  let closestMatch = null;
  let closestDistance = Infinity;

  if (!isKnownOfficial) {
    for (const d of trustedList) {
      const dist = levenshtein(reg, d);
      if (dist < closestDistance) {
        closestDistance = dist;
        closestMatch = d;
      }
    }
  }

  const looksLikeTyposquat = !isKnownOfficial && closestMatch !== null &&
    closestDistance > 0 && closestDistance <= 2 && reg.length > 5;

  let officialScore;
  if (isKnownOfficial) officialScore = 100;
  else if (looksLikeTyposquat) officialScore = 0;
  else officialScore = 65;

  return {
    domain,
    registrableDomain: reg,
    isKnownOfficial,
    looksLikeTyposquat,
    suspiciouslyCloseTo: looksLikeTyposquat ? closestMatch : null,
    officialWebsiteScore: officialScore,
    sourceReputationScore: isKnownOfficial ? 100 : looksLikeTyposquat ? 0 : 65
  };
}

export function verifyHttps(url) {
  const isHttps = url.startsWith("https://");
  return {
    isHttps,
    httpsScore: isHttps ? 100 : 0
  };
}

export function analyzeWebsiteVulnerabilities(url, headers = {}, extraTrustedDomains = []) {
  let domain = "";
  try {
    domain = new URL(url).hostname.toLowerCase();
  } catch {
    domain = url;
  }

  const sourceCheck = verifySource(domain, extraTrustedDomains);
  const isHttps = url.startsWith("https://");
  const vulnerabilities = [];

  const normalizedHeaders = {};
  for (const [k, v] of Object.entries(headers || {})) {
    normalizedHeaders[k.toLowerCase()] = String(v);
  }

  // 1. Protocol / HTTPS
  if (!isHttps) {
    vulnerabilities.push({
      key: "NO_HTTPS",
      ...VULNERABILITY_DEFINITIONS.NO_HTTPS
    });
  }

  // 2. Strict Transport Security (HSTS)
  const hsts = normalizedHeaders["strict-transport-security"];
  if (isHttps && !hsts) {
    vulnerabilities.push({
      key: "MISSING_HSTS",
      ...VULNERABILITY_DEFINITIONS.MISSING_HSTS
    });
  }

  // 3. Content Security Policy (CSP)
  const csp = normalizedHeaders["content-security-policy"];
  if (!csp) {
    vulnerabilities.push({
      key: "MISSING_CSP",
      ...VULNERABILITY_DEFINITIONS.MISSING_CSP
    });
  }

  // 4. Cross-Origin Resource Sharing (CORS)
  const corsOrigin = normalizedHeaders["access-control-allow-origin"];
  if (corsOrigin === "*") {
    vulnerabilities.push({
      key: "PERMISSIVE_CORS",
      ...VULNERABILITY_DEFINITIONS.PERMISSIVE_CORS
    });
  }

  // 5. Clickjacking (X-Frame-Options or CSP frame-ancestors)
  const xfo = normalizedHeaders["x-frame-options"];
  const hasFrameAncestors = csp && csp.includes("frame-ancestors");
  if (!xfo && !hasFrameAncestors) {
    vulnerabilities.push({
      key: "MISSING_CLICKJACKING_PROTECTION",
      ...VULNERABILITY_DEFINITIONS.MISSING_CLICKJACKING_PROTECTION
    });
  }

  // 6. MIME Sniffing Protection (X-Content-Type-Options)
  const xcto = normalizedHeaders["x-content-type-options"];
  if (!xcto || !xcto.toLowerCase().includes("nosniff")) {
    vulnerabilities.push({
      key: "MISSING_MIME_PROTECTION",
      ...VULNERABILITY_DEFINITIONS.MISSING_MIME_PROTECTION
    });
  }

  // 7. Typosquatting / Domain Spoofing
  if (sourceCheck.looksLikeTyposquat) {
    vulnerabilities.push({
      key: "TYPOSQUATTING_RISK",
      ...VULNERABILITY_DEFINITIONS.TYPOSQUATTING_RISK,
      unethicalHarm: `Phishing & Malware Delivery: Domain mimics "${sourceCheck.suspiciouslyCloseTo}". Users are likely being deceived into downloading malicious payloads disguised as official software.`
    });
  }

  // 8. TLD Risk Check
  const tld = domain.split(".").pop();
  if (SUSPICIOUS_TLDS.has(tld)) {
    vulnerabilities.push({
      key: "SUSPICIOUS_TLD",
      ...VULNERABILITY_DEFINITIONS.SUSPICIOUS_TLD
    });
  }

  let score = 100;
  if (!isHttps) score -= 40;
  if (sourceCheck.looksLikeTyposquat) score -= 45;
  if (!hsts) score -= 10;
  if (!csp) score -= 10;
  if (corsOrigin === "*") score -= 15;
  if (!xfo && !hasFrameAncestors) score -= 10;
  if (!xcto) score -= 5;
  if (SUSPICIOUS_TLDS.has(tld)) score -= 15;
  if (sourceCheck.isKnownOfficial) score += 10;

  score = Math.max(0, Math.min(100, Math.round(score)));

  let overallRisk = "safe";
  if (score < 50) overallRisk = "dangerous";
  else if (score < 80) overallRisk = "warning";

  return {
    url,
    domain,
    isHttps,
    isKnownOfficial: sourceCheck.isKnownOfficial,
    websiteSecurityScore: score,
    overallRisk,
    vulnerabilities,
    securityHeaders: {
      hsts: hsts || "Not Set",
      csp: csp ? "Configured" : "Not Set",
      cors: corsOrigin || "Default",
      xfo: xfo || "Not Set",
      xcto: xcto || "Not Set"
    }
  };
}