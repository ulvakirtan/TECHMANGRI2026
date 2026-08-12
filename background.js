// background.js
// Module 1: Download Monitor + top-level pipeline & Website Security orchestration.

import { parseDownloadItem } from "./modules/downloadParser.js";
import { verifySource, verifyHttps, analyzeWebsiteVulnerabilities } from "./modules/sourceVerification.js";
import { verifyPublisher } from "./modules/publisherVerification.js";
import { checkFileIntegrity } from "./modules/fileIntegrity.js";
import { checkVirusTotal, checkSafeBrowsing } from "./modules/threatIntelligence.js";
import { checkVulnerabilities } from "./modules/vulnerabilityIntelligence.js";
import { calculateTrustScore } from "./modules/trustEngine.js";
import { getRecommendation } from "./modules/recommendationEngine.js";
import { saveScanRecord, getSettings, getCached, setCached, getPublisherList } from "./modules/storageManager.js";

import { notifyResult } from "./modules/notificationEngine.js";
import { CACHE_TTL_MS } from "./modules/config.js";

const inFlight = new Map(); // downloadId -> { parsed, record }

chrome.downloads.onCreated.addListener(async (item) => {
  console.log("[SecureDownload AI] onCreated fired:", item.id, item.url, item.filename);

  const settings = await getSettings();
  if (!settings.autoAnalyze) {
    console.log("[SecureDownload AI] autoAnalyze is off — skipping.");
    return;
  }

  let freshItem = item;
  try {
    const [searched] = await chrome.downloads.search({ id: item.id });
    if (searched) freshItem = searched;
  } catch (err) {
    console.warn("[SecureDownload AI] downloads.search failed, using raw item", err);
  }

  const parsed = parseDownloadItem(freshItem);
  console.log("[SecureDownload AI] parsed download:", parsed);

  // Monitor & analyze ALL downloads (executables, archives, documents, scripts, media, code, etc.)
  try {
    await chrome.downloads.pause(item.id);
    console.log("[SecureDownload AI] paused download", item.id);
  } catch (err) {
    console.warn("[SecureDownload AI] could not pause (may already be complete):", err);
  }

  runAnalysisPipeline(parsed, settings)
    .then(() => console.log("[SecureDownload AI] pipeline complete for", parsed.filename))
    .catch(async (err) => {
      console.error("[SecureDownload AI] pipeline failed", err);
      try {
        await chrome.downloads.resume(item.id);
      } catch (resumeErr) {
        console.warn("[SecureDownload AI] could not resume download after failure:", resumeErr);
      }
      chrome.notifications.create(`sd_err_${item.id}`, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icons/icon128.png"),
        title: "⚠️ Security Audit Failure",
        message: `Download resumed unscanned: ${parsed.filename || "file"}.\nError: ${err.message || String(err)}`,
        priority: 1
      });
    });
});

async function runAnalysisPipeline(parsed, settings) {
  // Fetch site headers for vulnerability scanning
  const headers = await fetchSiteHeaders(parsed.url);
  const websiteSecurity = analyzeWebsiteVulnerabilities(parsed.url, headers, settings.extraTrustedDomains);

  // Run integrity check first so computed sha256 hash is passed to VirusTotal (Issue #4)
  const integrityResult = await checkFileIntegrity(parsed.url, settings.knownGoodHashes, parsed.filename);
  const vtKeyMaterial = integrityResult.sha256 || parsed.url;

  const publisherList = await getPublisherList();

  const [sourceResult, httpsResult, publisherResult, vtResult, sbResult, vulnResult] =
    await Promise.all([
      Promise.resolve(verifySource(parsed.domain, settings.extraTrustedDomains)),
      Promise.resolve(verifyHttps(parsed.url)),
      Promise.resolve(verifyPublisher(parsed, settings.extraTrustedDomains, publisherList)),

      cachedThreatCheck("vt", vtKeyMaterial, () => checkVirusTotal({ url: parsed.url, sha256: integrityResult.sha256 }, settings.virusTotalApiKey)),
      cachedThreatCheck("sb", parsed.url, () => checkSafeBrowsing(parsed.url, settings.safeBrowsingApiKey)),
      cachedThreatCheck("nvd", parsed.filename, () => checkVulnerabilities(parsed.filename, settings.nvdApiKey))
    ]);

  const trustResult = calculateTrustScore({
    officialWebsiteScore: sourceResult.officialWebsiteScore,
    publisherVerificationScore: publisherResult.publisherVerificationScore,
    vtScore: vtResult.vtScore,
    vtApplicable: vtResult.status !== "not_configured",
    vulnerabilityScore: vulnResult.vulnerabilityScore,
    vulnerabilityApplicable: !["no_version_detected", "error"].includes(vulnResult.status),
    httpsScore: httpsResult.httpsScore,
    integrityScore: integrityResult.integrityScore,
    integrityApplicable: ["matches_known_good", "hash_mismatch_possible_tampering"].includes(integrityResult.status),
    sourceReputationScore: sourceResult.sourceReputationScore,
    safeBrowsingFlagged: sbResult.flagged,
    chromeDanger: parsed.danger
  });

  const recommendation = getRecommendation(trustResult, {
    looksLikeTyposquat: sourceResult.looksLikeTyposquat,
    integrityStatus: integrityResult.status,
    chromeDanger: parsed.danger
  });

  const record = {
    downloadId: parsed.downloadId,
    filename: parsed.filename,
    extension: parsed.extension,
    category: parsed.category,
    url: parsed.url,
    domain: parsed.domain,
    scannedAt: new Date().toISOString(),
    trustScore: trustResult.trustScore,
    contributions: trustResult.contributions,
    checksApplicable: trustResult.checksApplicable,
    checksTotal: trustResult.checksTotal,
    riskLevel: recommendation.riskLevel,
    recommendation,
    websiteSecurity,
    details: {
      source: sourceResult,
      https: httpsResult,
      publisher: publisherResult,
      integrity: integrityResult,
      virusTotal: vtResult,
      safeBrowsing: sbResult,
      vulnerability: vulnResult,
      websiteSecurity
    },
    action: "pending"
  };

  const isSafe = recommendation.riskLevel === "safe";
  let autoResumed = false;

  if (isSafe) {
    try {
      await chrome.downloads.resume(parsed.downloadId);
      console.log("[SecureDownload AI] auto-resumed safe download", parsed.downloadId);
      record.action = "resumed";
      autoResumed = true;
    } catch (err) {
      console.warn("[SecureDownload AI] could not auto-resume download:", err);
    }
  }

  inFlight.set(parsed.downloadId, { parsed, record });
  await saveScanRecord(record);
  notifyResult(record, autoResumed);

  const settingsNow = await getSettings();
  if (settingsNow.blockDangerousByDefault && recommendation.riskLevel === "dangerous") {
    await resolveDownload(parsed.downloadId, "deleted");
  }

  chrome.runtime.sendMessage({ type: "SD_ANALYSIS_COMPLETE", record, autoResumed }).catch(() => {});
}

async function fetchSiteHeaders(url) {
  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 4000);
    let res = await fetch(url, { method: "HEAD", signal: controller.signal });
    clearTimeout(id);

    if (!res.ok || Array.from(res.headers.keys()).length === 0) {
      const getController = new AbortController();
      const getId = setTimeout(() => getController.abort(), 4000);
      res = await fetch(url, { method: "GET", headers: { Range: "bytes=0-0" }, signal: getController.signal });
      clearTimeout(getId);
    }

    const headers = {};
    for (const [k, v] of res.headers.entries()) {
      headers[k.toLowerCase()] = v;
    }
    return headers;
  } catch (err) {
    console.warn("[SecureDownload AI] could not fetch headers for", url, err);
    return {};
  }
}


async function cachedThreatCheck(prefix, keyMaterial, fn) {
  const cacheKey = `${prefix}:${keyMaterial}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;
  const result = await fn();
  await setCached(cacheKey, result, CACHE_TTL_MS[prefix === "vt" ? "virusTotal" : prefix === "sb" ? "safeBrowsing" : "nvd"]);
  return result;
}

async function resolveDownload(downloadId, action) {
  const entry = inFlight.get(downloadId);
  if (entry) {
    entry.record.action = action;
    await saveScanRecord(entry.record);
  }

  if (action === "resumed") {
    await chrome.downloads.resume(downloadId).catch(() => {});
  } else if (action === "deleted") {
    await chrome.downloads.cancel(downloadId).catch(() => {});
    await chrome.downloads.removeFile(downloadId).catch(() => {});
  }
  inFlight.delete(downloadId);
}

// Runtime message dispatcher
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "SD_GET_PENDING") {
    const pending = [...inFlight.values()].map((e) => e.record);
    sendResponse({ pending });
    return true;
  }
  if (message.type === "SD_RESOLVE_DOWNLOAD") {
    resolveDownload(message.downloadId, message.action).then(() => sendResponse({ ok: true }));
    return true;
  }
  if (message.type === "SD_ANALYZE_WEBSITE") {
    (async () => {
      const settings = await getSettings();
      const headers = await fetchSiteHeaders(message.url);
      const audit = analyzeWebsiteVulnerabilities(message.url, headers, settings.extraTrustedDomains);
      sendResponse({ audit });
    })();
    return true;
  }
  if (message.type === "SD_GET_ACTIVE_TAB_SECURITY") {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab || !tab.url || !tab.url.startsWith("http")) {
          sendResponse({ error: "No active HTTP/HTTPS webpage found." });
          return;
        }
        const settings = await getSettings();
        const headers = await fetchSiteHeaders(tab.url);
        const audit = analyzeWebsiteVulnerabilities(tab.url, headers, settings.extraTrustedDomains);
        sendResponse({ tabUrl: tab.url, tabTitle: tab.title, audit });
      } catch (err) {
        sendResponse({ error: String(err) });
      }
    })();
    return true;
  }
  return false;
});

chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
  const downloadId = Number(notificationId.replace("sd_", ""));
  const entry = inFlight.get(downloadId);
  if (!entry) return;

  const isDangerous = entry.record.riskLevel === "dangerous";
  if (isDangerous && buttonIndex === 0) {
    resolveDownload(downloadId, "deleted");
  } else {
    chrome.action.openPopup().catch(() => {});
  }
});
