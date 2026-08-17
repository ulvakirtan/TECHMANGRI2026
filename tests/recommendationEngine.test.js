import test from "node:test";
import assert from "node:assert/strict";
import { getRecommendation } from "../modules/recommendationEngine.js";

test("getRecommendation returns safe for high trust scores with no flags", () => {
  const result = getRecommendation(
    { trustScore: 85, safeBrowsingOverride: false },
    { looksLikeTyposquat: false, integrityStatus: "matches_known_good", chromeDanger: "safe" }
  );

  assert.equal(result.riskLevel, "safe");
  assert.equal(result.headline, "Safe to Install");
});

test("getRecommendation returns warning for moderate trust scores", () => {
  const result = getRecommendation(
    { trustScore: 65, safeBrowsingOverride: false },
    { looksLikeTyposquat: false, integrityStatus: "no_reference_hash", chromeDanger: "safe" }
  );

  assert.equal(result.riskLevel, "warning");
});

test("getRecommendation forces dangerous on Safe Browsing override", () => {
  const result = getRecommendation(
    { trustScore: 90, safeBrowsingOverride: true },
    { looksLikeTyposquat: false, integrityStatus: "matches_known_good", chromeDanger: "safe" }
  );

  assert.equal(result.riskLevel, "dangerous");
  assert.equal(result.headline, "Delete Immediately");
});

test("getRecommendation forces dangerous on typosquatting flag", () => {
  const result = getRecommendation(
    { trustScore: 85, safeBrowsingOverride: false },
    { looksLikeTyposquat: true, integrityStatus: "no_reference_hash", chromeDanger: "safe" }
  );

  assert.equal(result.riskLevel, "dangerous");
});

test("getRecommendation forces dangerous on hash mismatch", () => {
  const result = getRecommendation(
    { trustScore: 85, safeBrowsingOverride: false },
    { looksLikeTyposquat: false, integrityStatus: "hash_mismatch_possible_tampering", chromeDanger: "safe" }
  );

  assert.equal(result.riskLevel, "dangerous");
});

test("getRecommendation forces dangerous on Chrome danger flag", () => {
  const result = getRecommendation(
    { trustScore: 85, safeBrowsingOverride: false },
    { looksLikeTyposquat: false, integrityStatus: "no_reference_hash", chromeDanger: "unwanted" }
  );

  assert.equal(result.riskLevel, "dangerous");
});

test("getRecommendation returns blocked domain message for blocklist hits", () => {
  const result = getRecommendation(
    { trustScore: 0, safeBrowsingOverride: false },
    { blocklistMatch: "evil.com" }
  );

  assert.equal(result.riskLevel, "dangerous");
  assert.equal(result.headline, "Blocked Domain");
  assert.match(result.detail, /evil\.com/);
});
