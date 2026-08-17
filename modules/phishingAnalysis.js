// modules/phishingAnalysis.js
// Module 14: Phishing Analysis.
// Heuristic phishing/spoofing checks for a single parsed Gmail message.
// Deliberately reuses sourceVerification.js's typosquat/official-domain
// logic rather than duplicating it — a sender domain and a download domain
// are the same kind of trust question.
//
// CONSTRAINT: this runs in a service worker, which has no DOMParser. Link
// extraction from the HTML body is regex-based, not a real HTML parse —
// good enough to catch the common "visible text looks like a domain but
// href points elsewhere" pattern, but it can miss deliberately malformed
// or deeply nested markup a real parser would catch. Documented, not hidden.

import { KNOWN_PUBLISHERS, PHISHING_URGENCY_PATTERNS } from "./config.js";
import { verifySource } from "./sourceVerification.js";

const DOUBLE_EXTENSION_RX = /\.(pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|txt|csv)\.(exe|scr|bat|cmd|vbs|js|jar|ps1|com|pif)$/i;
const EXECUTABLE_ATTACHMENT_RX = /\.(exe|scr|bat|cmd|vbs|js|jar|ps1|com|pif|msi)$/i;

function parseFromHeader(fromHeader = "") {
  // "Display Name <email@domain.com>" or just "email@domain.com"
  const match = /^\s*"?([^"<]*)"?\s*<?([^<>\s]+@[^<>\s]+)>?\s*$/.exec(fromHeader);
  const displayName = (match?.[1] || "").trim();
  const email = (match?.[2] || fromHeader).trim().toLowerCase();
  const domain = email.split("@")[1] || "";
  return { displayName, email, domain };
}

function extractLinksFromHtml(html = "") {
  const links = [];
  const rx = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)<\/a>/gis;
  let m;
  while ((m = rx.exec(html)) !== null) {
    const href = m[1];
    const text = m[2].replace(/<[^>]+>/g, "").trim();
    if (href && text) links.push({ href, text });
  }
  return links;
}

function domainOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function detectDisplayNameSpoof(displayName, senderDomain) {
  if (!displayName) return null;
  const lower = displayName.toLowerCase();
  for (const publisher of KNOWN_PUBLISHERS) {
    if (lower.includes(publisher.name.toLowerCase())) {
      const domainMatches = publisher.domains.some((d) => senderDomain === d || senderDomain.endsWith(`.${d}`));
      if (!domainMatches) {
        return {
          key: "DISPLAY_NAME_SPOOF",
          severity: "critical",
          label: `Sender display name claims to be "${publisher.name}" but the address domain (${senderDomain}) doesn't match ${publisher.name}'s known domains`
        };
      }
    }
  }
  return null;
}

function detectUrgencyLanguage(text = "") {
  const matched = PHISHING_URGENCY_PATTERNS.filter((rx) => rx.test(text));
  if (matched.length === 0) return [];
  return [{
    key: "URGENCY_LANGUAGE",
    severity: matched.length >= 2 ? "critical" : "warning",
    label: `Contains ${matched.length} common phishing/urgency phrase pattern(s) (e.g. "verify your account", "act now")`
  }];
}

function detectLinkMismatches(links) {
  const findings = [];
  for (const link of links) {
    const hrefDomain = domainOf(link.href);
    if (!hrefDomain) continue;
    // Does the visible text itself look like a domain/URL?
    const textDomainMatch = link.text.match(/([a-z0-9-]+\.)+[a-z]{2,}/i);
    if (textDomainMatch) {
      const textDomain = textDomainMatch[0].toLowerCase();
      if (!hrefDomain.endsWith(textDomain) && !textDomain.endsWith(hrefDomain)) {
        findings.push({
          key: "LINK_TEXT_MISMATCH",
          severity: "critical",
          label: `A link displays "${textDomain}" but actually points to ${hrefDomain}`
        });
      }
    }
  }
  return findings;
}

function detectAttachmentRisk(attachments = []) {
  const findings = [];
  for (const att of attachments) {
    const name = att.filename || "";
    if (DOUBLE_EXTENSION_RX.test(name)) {
      findings.push({
        key: "DOUBLE_EXTENSION_ATTACHMENT",
        severity: "critical",
        label: `Attachment "${name}" uses a double extension to disguise an executable as a document`
      });
    } else if (EXECUTABLE_ATTACHMENT_RX.test(name)) {
      findings.push({
        key: "EXECUTABLE_ATTACHMENT",
        severity: "warning",
        label: `Attachment "${name}" is directly executable — verify the sender before opening`
      });
    }
  }
  return findings;
}

/**
 * @param {{from: string, subject: string, bodyText: string, bodyHtml: string, attachments: object[]}} message
 * @param {string[]} extraTrustedDomains
 */
export function analyzeEmailForPhishing(message, extraTrustedDomains = []) {
  const { displayName, email, domain } = parseFromHeader(message.from);
  const sourceCheck = verifySource(domain, extraTrustedDomains);
  const links = extractLinksFromHtml(message.bodyHtml);

  const findings = [
    ...(sourceCheck.looksLikeTyposquat
      ? [{
          key: "SENDER_DOMAIN_TYPOSQUAT",
          severity: "critical",
          label: `Sender domain "${domain}" closely mimics "${sourceCheck.suspiciouslyCloseTo}"`
        }]
      : []),
    ...[detectDisplayNameSpoof(displayName, domain)].filter(Boolean),
    ...detectUrgencyLanguage(`${message.subject}\n${message.bodyText}`),
    ...detectLinkMismatches(links),
    ...detectAttachmentRisk(message.attachments)
  ];

  const hasCritical = findings.some((f) => f.severity === "critical");
  const hasWarning = findings.some((f) => f.severity === "warning");

  let emailTrustScore = 95;
  if (hasCritical) emailTrustScore = 5;
  else if (hasWarning) emailTrustScore = 50;

  let riskLevel = "safe";
  if (hasCritical) riskLevel = "dangerous";
  else if (hasWarning) riskLevel = "warning";

  return {
    messageId: message.messageId,
    threadId: message.threadId,
    from: message.from,
    senderDisplayName: displayName,
    senderEmail: email,
    senderDomain: domain,
    subject: message.subject,
    isKnownOfficialSender: sourceCheck.isKnownOfficial,
    emailTrustScore,
    riskLevel,
    findings,
    attachmentCount: (message.attachments || []).length
  };
}
