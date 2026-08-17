import test from "node:test";
import assert from "node:assert/strict";
import {
  normalizeDomain,
  domainMatchesBlockEntry,
  checkDomainBlocklist
} from "../modules/domainBlocklist.js";

test("normalizeDomain lowercases and strips www", () => {
  assert.equal(normalizeDomain("WWW.Example.COM"), "example.com");
  assert.equal(normalizeDomain("  evil.com  "), "evil.com");
});

test("domainMatchesBlockEntry matches exact and subdomains only", () => {
  assert.equal(domainMatchesBlockEntry("evil.com", "evil.com"), true);
  assert.equal(domainMatchesBlockEntry("cdn.evil.com", "evil.com"), true);
  assert.equal(domainMatchesBlockEntry("www.evil.com", "evil.com"), true);
  assert.equal(domainMatchesBlockEntry("notevil.com", "evil.com"), false);
  assert.equal(domainMatchesBlockEntry("fakevil.com", "evil.com"), false);
});

test("checkDomainBlocklist finds first matching entry", () => {
  const result = checkDomainBlocklist("dl.badware.net", ["good.com", "badware.net"]);
  assert.equal(result.blocked, true);
  assert.equal(result.matchedEntry, "badware.net");
});

test("checkDomainBlocklist returns not blocked for empty list", () => {
  const result = checkDomainBlocklist("example.com", []);
  assert.equal(result.blocked, false);
  assert.equal(result.matchedEntry, null);
});
