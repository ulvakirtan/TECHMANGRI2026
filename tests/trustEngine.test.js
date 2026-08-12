import test from "node:test";
import assert from "node:assert/strict";
import { calculateTrustScore } from "../modules/trustEngine.js";

test("calculateTrustScore returns high score when all checks pass", () => {
  const result = calculateTrustScore({
    officialWebsiteScore: 100,
    publisherVerificationScore: 100,
    vtScore: 95,
    vtApplicable: true,
    vulnerabilityScore: 90,
    vulnerabilityApplicable: true,
    httpsScore: 100,
    integrityScore: 100,
    integrityApplicable: true,
    sourceReputationScore: 100,
    safeBrowsingFlagged: false,
    chromeDanger: "safe"
  });

  assert.equal(result.trustScore >= 95, true);
  assert.equal(result.safeBrowsingOverride, false);
  assert.equal(result.chromeDangerFlagged, false);
  assert.equal(result.checksApplicable, 7);
});

test("calculateTrustScore renormalizes weights when checks are not applicable", () => {
  const result = calculateTrustScore({
    officialWebsiteScore: 100,
    publisherVerificationScore: 100,
    vtScore: 50,
    vtApplicable: false,
    vulnerabilityScore: 70,
    vulnerabilityApplicable: false,
    httpsScore: 100,
    integrityScore: 50,
    integrityApplicable: false,
    sourceReputationScore: 100,
    safeBrowsingFlagged: false,
    chromeDanger: "safe"
  });

  assert.equal(result.trustScore, 100);
  assert.equal(result.checksApplicable, 4);
});

test("calculateTrustScore caps score when safeBrowsing is flagged", () => {
  const result = calculateTrustScore({
    officialWebsiteScore: 100,
    publisherVerificationScore: 100,
    vtScore: 100,
    vtApplicable: true,
    vulnerabilityScore: 100,
    vulnerabilityApplicable: true,
    httpsScore: 100,
    integrityScore: 100,
    integrityApplicable: true,
    sourceReputationScore: 100,
    safeBrowsingFlagged: true,
    chromeDanger: "safe"
  });

  assert.equal(result.safeBrowsingOverride, true);
  assert.equal(result.trustScore <= 10, true);
});

test("calculateTrustScore caps score when chromeDanger is flagged", () => {
  const result = calculateTrustScore({
    officialWebsiteScore: 100,
    publisherVerificationScore: 100,
    vtScore: 100,
    vtApplicable: true,
    vulnerabilityScore: 100,
    vulnerabilityApplicable: true,
    httpsScore: 100,
    integrityScore: 100,
    integrityApplicable: true,
    sourceReputationScore: 100,
    safeBrowsingFlagged: false,
    chromeDanger: "dangerous"
  });

  assert.equal(result.chromeDangerFlagged, true);
  assert.equal(result.trustScore <= 10, true);
});
