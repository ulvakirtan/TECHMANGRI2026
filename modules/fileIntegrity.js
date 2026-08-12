// modules/fileIntegrity.js
// Module 5: File Integrity.
// Direct URL Byte Hash Engine.
// TRADEOFF NOTE (Issue #8): WebExtensions Manifest V3 background service workers
// cannot inspect paused download files on local disk prior to completion without
// native messaging binaries. Thus, fileIntegrity fetches content bytes via HTTP.
// To avoid excessive bandwidth/memory consumption, downloads larger than 200MB
// (or exceeding Content-Length threshold) skip this check cleanly.

const MAX_BYTES_TO_HASH = 200 * 1024 * 1024; // 200MB safety cap


function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * @param {string} url
 * @param {Record<string,string>} knownGoodHashes - filename/publisher -> expected sha256
 * @param {string} filename
 */
export async function checkFileIntegrity(url, knownGoodHashes = {}, filename = "") {
  try {
    const response = await fetch(url, { credentials: "omit" });
    if (!response.ok) {
      return { integrityScore: 50, status: "fetch_failed", sha256: null };
    }

    const contentLength = Number(response.headers.get("content-length") || 0);
    if (contentLength > MAX_BYTES_TO_HASH) {
      return { integrityScore: 60, status: "skipped_too_large", sha256: null };
    }

    const buffer = await response.arrayBuffer();
    const digest = await crypto.subtle.digest("SHA-256", buffer);
    const sha256 = bufToHex(digest);

    const expected = knownGoodHashes[filename.toLowerCase()];
    if (!expected) {
      return { integrityScore: 55, status: "no_reference_hash", sha256 };
    }

    const matches = expected.toLowerCase() === sha256.toLowerCase();
    return {
      integrityScore: matches ? 100 : 0,
      status: matches ? "matches_known_good" : "hash_mismatch_possible_tampering",
      sha256,
      expectedHash: expected
    };
  } catch (err) {
    return { integrityScore: 50, status: "error", error: String(err), sha256: null };
  }
}
