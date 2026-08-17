// modules/emailAuth.js
// Module 12: Email Auth.
// Uses chrome.identity.getAuthToken() with the OAuth Client ID pinned in
// manifest.json's "oauth2" key, instead of launchWebAuthFlow() with a
// per-session, user-typed Client ID. This is the simpler of the two valid
// approaches: Chrome handles token caching and silent refresh internally,
// there's no custom popup/redirect parsing, and "Connect Gmail" is a single
// click with Chrome's native account picker.
//
// Tradeoff, stated plainly: the Client ID is now fixed in manifest.json —
// switching Google accounts means either signing into that account as your
// Chrome profile's primary identity, or editing manifest.json and reloading
// the extension. For a single-user personal build, that's a reasonable
// trade for not having to paste a Client ID into Settings.
//
// Scope requested: gmail.readonly — the least-privileged scope that still
// allows reading message content for phishing analysis. This extension
// never requests send/modify/delete scopes and never could, even if asked,
// without a manifest change + re-review.

/**
 * Interactive connect — shows Chrome's native account chooser / consent
 * screen if needed. Must be called from a click handler (popup or options).
 */
export async function connectGmail() {
  try {
    const token = await getAuthTokenPromise({ interactive: true });
    return token ? { ok: true } : { ok: false, error: "No token returned — connection was cancelled." };
  } catch (err) {
    return { ok: false, error: friendlyAuthError(err) };
  }
}

/**
 * Silent (no prompt) token fetch — used by the periodic scan alarm and by
 * any pipeline call that just needs a valid token. Chrome caches and
 * refreshes the token itself; this only prompts if interactive is true.
 * Returns null on failure so callers can surface "reconnect Gmail" instead
 * of failing silently forever.
 */
export async function getValidAccessToken() {
  try {
    return await getAuthTokenPromise({ interactive: false });
  } catch {
    return null;
  }
}

export async function isGmailConnected() {
  const token = await getValidAccessToken();
  return Boolean(token);
}

export async function disconnectGmail() {
  try {
    const token = await getAuthTokenPromise({ interactive: false });
    if (token) {
      await new Promise((resolve) => chrome.identity.removeCachedAuthToken({ token }, resolve));
      // Best-effort revoke at Google's end too — don't block disconnect on it.
      fetch(`https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(token)}`, { method: "POST" }).catch(() => {});
    }
  } catch {
    // Nothing cached — already effectively disconnected.
  }
}

function getAuthTokenPromise(details) {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken(details, (token) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(token || null);
    });
  });
}

function friendlyAuthError(err) {
  const msg = String(err?.message || err || "");
  if (/OAuth2 not granted or revoked/i.test(msg)) {
    return "Connection was cancelled or access was revoked.";
  }
  if (/bad client id/i.test(msg)) {
    return "manifest.json's oauth2.client_id isn't set up correctly — check the Client ID in Google Cloud Console.";
  }
  return msg || "Could not connect to Gmail.";
}
