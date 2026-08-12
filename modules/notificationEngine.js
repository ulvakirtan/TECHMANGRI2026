// modules/notificationEngine.js
// Module 11: Notification Engine.

export function notifyResult(record, autoResumed = false) {
  const { filename, trustScore, recommendation, action } = record;

  let title = `${recommendation.emoji} ${recommendation.headline}`;
  if (autoResumed || action === "resumed") {
    title = `🟢 Verified Safe (Score: ${trustScore}) — Download Continuing`;
  } else if (action === "deleted") {
    title = `🔴 DANGEROUS DOWNLOAD BLOCKED & DELETED (Score: ${trustScore})`;
  } else if (recommendation.riskLevel === "dangerous") {
    title = `🔴 DANGEROUS DOWNLOAD PAUSED — ACTION REQUIRED (Score: ${trustScore})`;
  } else {
    title = `🟡 Download Paused for Audit: ${recommendation.headline}`;
  }


  const buttons = autoResumed
    ? [{ title: "View Analysis" }]
    : recommendation.riskLevel === "dangerous"
      ? [{ title: "Delete File" }, { title: "View Details" }]
      : [{ title: "Resume Download" }, { title: "View Details" }];

  chrome.notifications.create(`sd_${record.downloadId}`, {
    type: "basic",
    iconUrl: chrome.runtime.getURL("icons/icon128.png"),
    title,
    message: `${filename}\nTrust Score: ${trustScore}/100 — ${recommendation.detail}`,
    priority: recommendation.riskLevel === "dangerous" ? 2 : 1,
    buttons
  });
}

