// options/options.js

import { getSettings, saveSettings } from "../modules/storageManager.js";

const els = {
  vtKey: document.getElementById("vtKey"),
  sbKey: document.getElementById("sbKey"),
  nvdKey: document.getElementById("nvdKey"),
  autoAnalyze: document.getElementById("autoAnalyze"),
  blockDangerous: document.getElementById("blockDangerous"),
  trustedDomains: document.getElementById("trustedDomains"),
  knownHashes: document.getElementById("knownHashes"),
  saveBtn: document.getElementById("saveBtn"),
  savedMsg: document.getElementById("savedMsg")
};

init();

async function init() {
  const settings = await getSettings();
  els.vtKey.value = settings.virusTotalApiKey || "";
  els.sbKey.value = settings.safeBrowsingApiKey || "";
  els.nvdKey.value = settings.nvdApiKey || "";
  els.autoAnalyze.checked = settings.autoAnalyze !== false;
  els.blockDangerous.checked = Boolean(settings.blockDangerousByDefault);
  els.trustedDomains.value = (settings.extraTrustedDomains || []).join("\n");
  els.knownHashes.value = Object.entries(settings.knownGoodHashes || {})
    .map(([name, hash]) => `${name} = ${hash}`)
    .join("\n");

  els.saveBtn.addEventListener("click", onSave);
}

async function onSave() {
  const extraTrustedDomains = els.trustedDomains.value
    .split("\n")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  const knownGoodHashes = {};
  for (const line of els.knownHashes.value.split("\n")) {
    const [name, hash] = line.split("=").map((s) => s && s.trim());
    if (name && hash) knownGoodHashes[name.toLowerCase()] = hash;
  }

  await saveSettings({
    virusTotalApiKey: els.vtKey.value.trim(),
    safeBrowsingApiKey: els.sbKey.value.trim(),
    nvdApiKey: els.nvdKey.value.trim(),
    autoAnalyze: els.autoAnalyze.checked,
    blockDangerousByDefault: els.blockDangerous.checked,
    extraTrustedDomains,
    knownGoodHashes
  });

  els.savedMsg.classList.remove("hidden");
  setTimeout(() => els.savedMsg.classList.add("hidden"), 1800);
}
