// modules/emailAuth.js
// Module 12: Email Auth.
// Handles the Gmail OAuth flow. Deliberately uses chrome.identity.launchWebAuthFlow()
// with a user-supplied OAuth client ID (entered in Settings) rather than
// chrome.identity.getAuthToken() with a client_id baked into manifest.json —
// consistent with the rest of this project's "nothing requires a rebuild"
// design, and it means SecureDownload AI itself never holds a shared client
// secret. Each user creates their own OAuth client in Google Cloud Console
// and authorizes it against their own Google account only.
//
// Scope requested: gmail.readonly — the least-privileged scope that still
// allows reading message content for phishing analysis. This extension
// never requests send/modify/delete scopes and never could, even if asked,
// without a manifest + re-review.

import { GMAIL_SCOPE } from "./config.js";

const TOKEN_KEY = "sd_gmail_token"; // { accessToken, expiresAt }
const CLIENT_ID_KEY_IN_SETTINGS = "gmailOAuthClientId";

function authUrl(clientId, redirectUri) {
  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "token",
    redirect_uri: redirectUri,
    scope: GMAIL_SCOPE,
    prompt: "consent",
    include_granted_scopes: "true"
  });
  return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
}

function parseTokenFromRedirect(redirectUrl) {
  const fragment = redirectUrl.split("#")[1] || "";
  const params = new URLSearchParams(fragment);
  const accessToken = params.get("access_token");
  const expiresIn = Number(params.get("expires_in") || 3600);
  const error = params.get("error");
  if (error) throw new Error(`Google OAuth error: ${error}`);
  if (!accessToken) throw new Error("No access_token in OAuth redirect");
  return { accessToken, expiresAt: Date.now() + expiresIn * 1000 };
}

/**
 * Interactive (user-gesture-required) connect. Must be called from a click
 * handler in an extension page (popup or options) — service workers can
 * call chrome.identity APIs but launchWebAuthFlow with interactive:true
 * needs the call to originate from a page with a recent user gesture.
 * @param {string} clientId
 */
export async function connectGmail(clientId) {
  if (!clientId || !clientId.trim()) {
    return { ok: false, error: "Enter your Google OAuth Client ID first (see Settings for setup steps)." };
  }
  const redirectUri = chrome.identity.getRedirectURL();
  try {
    const redirectUrl = await chrome.identity.launchWebAuthFlow({
      url: authUrl(clientId.trim(), redirectUri),
      interactive: true
    });
    const token = parseTokenFromRedirect(redirectUrl);
    await chrome.storage.local.set({ [TOKEN_KEY]: token, [CLIENT_ID_KEY_IN_SETTINGS]: clientId.trim() });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err.message || err) };
  }
}

/**
 * Silent (no prompt) token refresh — used by the periodic scan alarm. Only
 * succeeds if the user still has an active Google session and previously
 * granted consent; otherwise returns null so the caller can surface
 * "reconnect Gmail" instead of failing silently forever.
 */
export async function getValidAccessToken() {
  const { [TOKEN_KEY]: token } = await chrome.storage.local.get(TOKEN_KEY);
  if (token && token.expiresAt > Date.now() + 60_000) {
    return token.accessToken;
  }

  const { [CLIENT_ID_KEY_IN_SETTINGS]: clientId } = await chrome.storage.local.get(CLIENT_ID_KEY_IN_SETTINGS);
  if (!clientId) return null;

  try {
    const redirectUri = chrome.identity.getRedirectURL();
    const redirectUrl = await chrome.identity.launchWebAuthFlow({
      url: authUrl(clientId, redirectUri),
      interactive: false
    });
    const refreshed = parseTokenFromRedirect(redirectUrl);
    await chrome.storage.local.set({ [TOKEN_KEY]: refreshed });
    return refreshed.accessToken;
  } catch {
    return null; // silent refresh failed — caller should prompt for reconnect
  }
}

export async function isGmailConnected() {
  const { [TOKEN_KEY]: token } = await chrome.storage.local.get(TOKEN_KEY);
  return Boolean(token && token.accessToken);
}

export async function disconnectGmail() {
  const { [TOKEN_KEY]: token } = await chrome.storage.local.get(TOKEN_KEY);
  if (token?.accessToken) {
    // Best-effort revoke — don't block disconnect on it.
    fetch(`https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(token.accessToken)}`, { method: "POST" }).catch(() => {});
  }
  await chrome.storage.local.remove(TOKEN_KEY);
}

export async function getStoredClientId() {
  const { [CLIENT_ID_KEY_IN_SETTINGS]: clientId } = await chrome.storage.local.get(CLIENT_ID_KEY_IN_SETTINGS);
  return clientId || "";
}
