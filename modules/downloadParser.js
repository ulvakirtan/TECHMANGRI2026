// modules/downloadParser.js
// Module 2 of the pipeline: Download Parser.
// Takes the raw chrome.downloads.DownloadItem and normalizes it into a
// stable shape the rest of the pipeline (and the popup UI) can rely on,
// regardless of what Chrome's API happens to include on a given platform.

import {
  EXECUTABLE_EXTENSIONS,
  ARCHIVE_EXTENSIONS,
  DOCUMENT_EXTENSIONS,
  SCRIPT_EXTENSIONS,
  MEDIA_EXTENSIONS,
  CODE_EXTENSIONS
} from "./config.js";

function getExtension(filename = "") {
  const match = /\.([a-zA-Z0-9]+)$/.exec(filename);
  return match ? match[1].toLowerCase() : "";
}

function getExtensionFromUrl(url = "") {
  try {
    const pathname = new URL(url).pathname;
    return getExtension(pathname);
  } catch {
    return "";
  }
}

function getDomain(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function getFileCategory(ext = "") {
  if (EXECUTABLE_EXTENSIONS.has(ext)) return "executable";
  if (ARCHIVE_EXTENSIONS.has(ext)) return "archive";
  if (DOCUMENT_EXTENSIONS.has(ext)) return "document";
  if (SCRIPT_EXTENSIONS.has(ext)) return "script";
  if (MEDIA_EXTENSIONS.has(ext)) return "media";
  if (CODE_EXTENSIONS.has(ext)) return "code";
  return "other";
}

/**
 * @param {chrome.downloads.DownloadItem} item
 * @returns {object} normalized download descriptor
 */
export function parseDownloadItem(item) {
  const rawFilename = (item.filename || "").split(/[\\/]/).pop();
  const url = item.finalUrl || item.url || "";
  const extension = getExtension(rawFilename || "") || getExtensionFromUrl(url);
  const filename = rawFilename || (url.split("/").pop().split("?")[0] || "download");
  const domain = getDomain(url);
  const category = getFileCategory(extension);

  return {
    downloadId: item.id,
    url,
    originalUrl: item.url,
    referrer: item.referrer || "",
    filename,
    extension,
    category,
    mimeType: item.mime || "application/octet-stream",
    fileSizeBytes: item.fileSize ?? item.totalBytes ?? -1,
    domain,
    isHttps: url.startsWith("https://"),
    isExecutable: category === "executable",
    isArchive: category === "archive",
    isDocument: category === "document",
    isScript: category === "script",
    startTimeIso: item.startTime || new Date().toISOString(),
    danger: item.danger || "safe",
    state: item.state || "in_progress"
  };
}

