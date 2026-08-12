// modules/recommendationEngine.js
// Module 9: Recommendation Engine.
// Translates a numeric trust score (plus a couple of specific red flags)
// into a plain-language recommendation and risk tier for the UI/notification.

import { RISK_THRESHOLDS } from "./config.js";

export function getRecommendation(trustResult, context = {}) {
  const { trustScore, safeBrowsingOverride } = trustResult;
  const { looksLikeTyposquat, integrityStatus } = context;

  if (safeBrowsingOverride) {
    return {
      riskLevel: "dangerous",
      emoji: "🔴",
      headline: "Delete Immediately",
      detail: "Google Safe Browsing has flagged this download's source as a known threat."
    };
  }

  if (looksLikeTyposquat) {
    return {
      riskLevel: "dangerous",
      emoji: "🔴",
      headline: "Delete Immediately",
      detail: "This domain closely mimics a known official publisher — a common impersonation tactic."
    };
  }

  if (integrityStatus === "hash_mismatch_possible_tampering") {
    return {
      riskLevel: "dangerous",
      emoji: "🔴",
      headline: "Delete Immediately",
      detail: "The file's hash doesn't match the known-good reference. It may have been tampered with."
    };
  }

  if (trustScore >= RISK_THRESHOLDS.safe) {
    return {
      riskLevel: "safe",
      emoji: "🟢",
      headline: "Safe to Install",
      detail: "This download passed source, publisher, and threat-intelligence checks."
    };
  }

  if (trustScore >= RISK_THRESHOLDS.caution) {
    return {
      riskLevel: "warning",
      emoji: "🟡",
      headline: "Proceed with Caution",
      detail: "Some checks were inconclusive or unfavorable. Prefer installing only from the official site."
    };
  }

  return {
    riskLevel: "dangerous",
    emoji: "🔴",
    headline: "Delete Immediately",
    detail: "Multiple checks indicate this file is unsafe."
  };
}
