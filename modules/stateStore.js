// modules/stateStore.js
// Module 1b: State Store.
// Tracks in-flight (awaiting-user-decision) download scans in
// chrome.storage.session instead of an in-memory Map. An in-memory Map is
// wiped whenever Chrome kills an idle MV3 service worker (routine, not
// exceptional) — a download paused for review could become untrackable
// mid-review. chrome.storage.session survives worker restarts but is still
// cleared when the browser closes, so it never leaks into disk storage.
//
// Entries are removed as soon as a download is resolved — including
// auto-resume — not just on explicit user action. Keeping resolved entries
// around indefinitely (a bug in the reference implementation this was
// ported from) makes storage.session grow without bound over a long
// session and makes "in-flight" a misleading label for data that also
// includes every already-resolved scan.

/**
 * @param {number} downloadId
 * @param {{parsed: object, record: object}} entry
 */
export async function setInFlightScan(downloadId, entry) {
  const key = `inflight_${downloadId}`;
  await chrome.storage.session.set({ [key]: entry });
}

/**
 * @param {number} downloadId
 * @returns {Promise<{parsed: object, record: object}|null>}
 */
export async function getInFlightScan(downloadId) {
  const key = `inflight_${downloadId}`;
  const result = await chrome.storage.session.get(key);
  return result[key] || null;
}

/**
 * @param {number} downloadId
 */
export async function removeInFlightScan(downloadId) {
  const key = `inflight_${downloadId}`;
  await chrome.storage.session.remove(key);
}

/**
 * Returns all currently-tracked scans. Because entries are removed on
 * resolution (see module comment), everything this returns is genuinely
 * awaiting a user decision — safe to treat the length as a "needs
 * attention" count.
 * @returns {Promise<object[]>}
 */
export async function getAllInFlightScans() {
  const all = await chrome.storage.session.get(null);
  const records = [];
  for (const [key, val] of Object.entries(all)) {
    if (key.startsWith("inflight_") && val && val.record) {
      records.push(val.record);
    }
  }
  // Most recent first — popup shows records[0] when nothing else to show.
  records.sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt));
  return records;
}
