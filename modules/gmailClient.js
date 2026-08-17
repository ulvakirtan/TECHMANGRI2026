// modules/gmailClient.js
// Module 13: Gmail Client.
// Thin wrapper around the Gmail REST API (read-only). Normalizes a raw
// Gmail message resource into the plain shape phishingAnalysis.js expects:
// sender, subject, links, plain-text body, and attachment metadata.

import { ENDPOINTS } from "./config.js";

function base64UrlDecode(str) {
  try {
    const normalized = str.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "===".slice((normalized.length + 3) % 4);
    // atob is available in MV3 service workers.
    return decodeURIComponent(
      Array.prototype.map
        .call(atob(padded), (c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0"))
        .join("")
    );
  } catch {
    return "";
  }
}

async function gmailFetch(url, accessToken) {
  const res = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (res.status === 401) throw new Error("gmail_unauthorized");
  if (!res.ok) throw new Error(`Gmail API error: ${res.status}`);
  return res.json();
}

/**
 * @param {string} accessToken
 * @param {number} maxResults
 */
export async function listRecentMessageIds(accessToken, maxResults = 25) {
  const params = new URLSearchParams({
    maxResults: String(maxResults),
    q: "in:inbox newer_than:7d" // scope to recent inbox mail, not the whole account history
  });
  const data = await gmailFetch(`${ENDPOINTS.gmailMessages}?${params.toString()}`, accessToken);
  return (data.messages || []).map((m) => m.id);
}

function findHeader(headers, name) {
  const h = (headers || []).find((x) => x.name?.toLowerCase() === name.toLowerCase());
  return h?.value || "";
}

function extractBodyAndAttachments(payload) {
  let plainText = "";
  let html = "";
  const attachments = [];

  function walk(part) {
    if (!part) return;
    const mimeType = part.mimeType || "";
    if (mimeType === "text/plain" && part.body?.data) {
      plainText += base64UrlDecode(part.body.data);
    } else if (mimeType === "text/html" && part.body?.data) {
      html += base64UrlDecode(part.body.data);
    } else if (part.filename && part.filename.length > 0) {
      attachments.push({ filename: part.filename, mimeType });
    }
    (part.parts || []).forEach(walk);
  }

  walk(payload);
  return { plainText, html, attachments };
}

/**
 * @param {string} accessToken
 * @param {string} messageId
 */
export async function getMessage(accessToken, messageId) {
  const data = await gmailFetch(`${ENDPOINTS.gmailMessages}/${messageId}?format=full`, accessToken);
  const headers = data.payload?.headers || [];
  const { plainText, html, attachments } = extractBodyAndAttachments(data.payload);

  return {
    messageId: data.id,
    threadId: data.threadId,
    from: findHeader(headers, "From"),
    subject: findHeader(headers, "Subject"),
    dateHeader: findHeader(headers, "Date"),
    snippet: data.snippet || "",
    bodyText: plainText || "",
    bodyHtml: html || "",
    attachments
  };
}
