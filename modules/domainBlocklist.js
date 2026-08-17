// modules/domainBlocklist.js
// User-defined blocklist check. Kept as a pure module so matching rules
// are easy to unit-test without touching chrome APIs.

/**
 * Normalize a domain for comparison: lowercase, strip leading "www.".
 * @param {string} domain
 * @returns {string}
 */
export function normalizeDomain(domain) {
  if (typeof domain !== "string") return "";
  let d = domain.trim().toLowerCase();
  if (d.startsWith("www.")) d = d.slice(4);
  return d;
}

/**
 * Returns true when `domain` exactly matches `blockedEntry`, or is a
 * subdomain of it (e.g. blocking "evil.com" also blocks "cdn.evil.com").
 * Does NOT match suffix lookalikes like "notevil.com".
 *
 * @param {string} domain
 * @param {string} blockedEntry
 */
export function domainMatchesBlockEntry(domain, blockedEntry) {
  const d = normalizeDomain(domain);
  const b = normalizeDomain(blockedEntry);
  if (!d || !b) return false;
  return d === b || d.endsWith(`.${b}`);
}

/**
 * @param {string} domain
 * @param {string[]} blocklist
 * @returns {{ blocked: boolean, matchedEntry: string | null }}
 */
export function checkDomainBlocklist(domain, blocklist = []) {
  if (!Array.isArray(blocklist) || blocklist.length === 0) {
    return { blocked: false, matchedEntry: null };
  }

  for (const entry of blocklist) {
    if (domainMatchesBlockEntry(domain, entry)) {
      return { blocked: true, matchedEntry: normalizeDomain(entry) };
    }
  }

  return { blocked: false, matchedEntry: null };
}

/** Alias used by background.js — same function, clearer call-site name. */
export const isDomainBlocked = checkDomainBlocklist;
