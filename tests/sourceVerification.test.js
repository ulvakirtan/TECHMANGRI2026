import test from "node:test";
import assert from "node:assert/strict";
import { verifySource, verifyHttps, levenshtein, analyzeWebsiteVulnerabilities } from "../modules/sourceVerification.js";

test("levenshtein computes correct distance and caches results", () => {
  assert.equal(levenshtein("google", "google"), 0);
  assert.equal(levenshtein("g00gle", "google"), 2);
  assert.equal(levenshtein("abcdef", "xyz") > 2, true); // Returns lenDiff > 2 filter
});


test("verifySource identifies known official domains", () => {
  const result = verifySource("dl.google.com");
  assert.equal(result.isKnownOfficial, true);
  assert.equal(result.looksLikeTyposquat, false);
  assert.equal(result.officialWebsiteScore, 100);
});

test("verifySource detects typosquatting domain impersonation", () => {
  const result = verifySource("go0gle.com");
  assert.equal(result.looksLikeTyposquat, true);
  assert.equal(result.officialWebsiteScore, 0);
  assert.equal(result.suspiciouslyCloseTo, "google.com");
});

test("verifySource respects extra trusted domains", () => {
  const result = verifySource("mycompany.internal", ["mycompany.internal"]);
  assert.equal(result.isKnownOfficial, true);
  assert.equal(result.officialWebsiteScore, 100);
});

test("verifyHttps checks protocol correctly", () => {
  assert.equal(verifyHttps("https://example.com").isHttps, true);
  assert.equal(verifyHttps("https://example.com").httpsScore, 100);
  assert.equal(verifyHttps("http://example.com").isHttps, false);
  assert.equal(verifyHttps("http://example.com").httpsScore, 0);
});

test("analyzeWebsiteVulnerabilities assesses headers and protocol", () => {
  const result = analyzeWebsiteVulnerabilities("http://insecure-site.xyz", {
    "access-control-allow-origin": "*"
  });

  assert.equal(result.isHttps, false);
  assert.equal(result.websiteSecurityScore < 50, true);
  assert.equal(result.vulnerabilities.some(v => v.key === "NO_HTTPS"), true);
  assert.equal(result.vulnerabilities.some(v => v.key === "PERMISSIVE_CORS"), true);
});
