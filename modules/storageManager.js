// modules/storageManager.js
// Module 10: Storage Manager.
// Single place that touches chrome.storage.local, so every other module
// deals with plain JS objects instead of the callback/promise storage API.

import { MAX_HISTORY_ITEMS, CACHE_TTL_MS } from "./config.js";

const KEYS = {
  history: "sd_history",
  stats: "sd_stats",
  cache: "sd_cache",           // { [cacheKey]: { value, expiresAt } }
  settings: "sd_settings"      // API keys, trusted domains, known-good hashes
};

export async function saveScanRecord(record) {
  const { [KEYS.history]: history = [] } = await chrome.storage.local.get(KEYS.history);
  const existingIdx = history.findIndex(h => h.downloadId === record.downloadId);
  let updated;
  if (existingIdx >= 0) {
    updated = [...history];
    updated[existingIdx] = record;
  } else {
    updated = [record, ...history].slice(0, MAX_HISTORY_ITEMS);
    await bumpStats(record);
  }
  await chrome.storage.local.set({ [KEYS.history]: updated });
  return updated;
}


export async function getHistory() {
  const { [KEYS.history]: history = [] } = await chrome.storage.local.get(KEYS.history);
  return history;
}

export async function getStats() {
  const { [KEYS.stats]: stats = defaultStats() } = await chrome.storage.local.get(KEYS.stats);
  return stats;
}

function defaultStats() {
  return { totalScanned: 0, safe: 0, warning: 0, dangerous: 0, filesBlocked: 0 };
}

async function bumpStats(record) {
  const stats = await getStats();
  stats.totalScanned += 1;
  if (record.riskLevel === "safe") stats.safe += 1;
  else if (record.riskLevel === "warning") stats.warning += 1;
  else if (record.riskLevel === "dangerous") stats.dangerous += 1;
  if (record.action === "deleted") stats.filesBlocked += 1;
  await chrome.storage.local.set({ [KEYS.stats]: stats });
}

export async function getCached(key) {
  const { [KEYS.cache]: cache = {} } = await chrome.storage.local.get(KEYS.cache);
  const entry = cache[key];
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) return null;
  return entry.value;
}

export async function setCached(key, value, ttlMs = CACHE_TTL_MS.virusTotal) {
  const { [KEYS.cache]: cache = {} } = await chrome.storage.local.get(KEYS.cache);
  cache[key] = { value, expiresAt: Date.now() + ttlMs };
  await chrome.storage.local.set({ [KEYS.cache]: cache });
}

export async function getSettings() {
  const { [KEYS.settings]: settings = defaultSettings() } = await chrome.storage.local.get(KEYS.settings);
  return settings;
}

export async function saveSettings(partial) {
  const current = await getSettings();
  const updated = { ...current, ...partial };
  await chrome.storage.local.set({ [KEYS.settings]: updated });
  return updated;
}

function defaultSettings() {
  return {
    virusTotalApiKey: "",
    safeBrowsingApiKey: "",
    nvdApiKey: "",
    extraTrustedDomains: [],
    knownGoodHashes: {},        // { filename_lowercase: sha256 }
    autoAnalyze: true,
    blockDangerousByDefault: false
  };
}
