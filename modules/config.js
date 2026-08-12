// modules/config.js
// Central configuration: weights, endpoints, defaults.
// Nothing here should require a rebuild to change — everything user-tunable
// (API keys, extra trusted domains) lives in chrome.storage, not this file.

export const WEIGHTS = {
  officialWebsite: 0.20,
  publisherVerification: 0.20,
  virusTotal: 0.20,
  vulnerability: 0.15,
  https: 0.10,
  fileIntegrity: 0.10,
  sourceReputation: 0.05
};

// Sanity check at load time — if these ever drift from 1.0 the formula in
// trustEngine.js silently produces a score out of the wrong range.
export const WEIGHT_SUM = Object.values(WEIGHTS).reduce((a, b) => a + b, 0);

if (Math.abs(WEIGHT_SUM - 1.0) > 0.0001) {
  throw new Error(`[SecureDownload AI] Invalid weight configuration: WEIGHT_SUM is ${WEIGHT_SUM}, must equal 1.0`);
}

export const RISK_THRESHOLDS = {
  safe: 80,      // >= 80  -> Safe to Install / Visit
  caution: 50,   // 50-79  -> Proceed with Caution / Verify Official Site
  danger: 0      // < 50   -> Delete Immediately / High Risk
};

export const EXECUTABLE_EXTENSIONS = new Set([
  "exe", "msi", "msix", "appx", "dmg", "pkg", "app",
  "deb", "rpm", "appimage", "sh", "bat", "cmd", "ps1",
  "jar", "apk", "vbs", "com", "gadget"
]);

export const ARCHIVE_EXTENSIONS = new Set([
  "zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "iso", "img", "cab"
]);

export const DOCUMENT_EXTENSIONS = new Set([
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "txt", "csv"
]);

export const SCRIPT_EXTENSIONS = new Set([
  "js", "ts", "py", "rb", "php", "pl", "sh", "ps1", "bat", "cmd", "vbs", "wsf"
]);

export const MEDIA_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "svg", "webp", "mp3", "wav", "mp4", "mkv", "avi", "mov"
]);

export const CODE_EXTENSIONS = new Set([
  "c", "cpp", "h", "cs", "java", "go", "rs", "html", "css", "json", "xml", "yaml", "yml", "sql"
]);

// Seed list of well-known software publishers and their official domains + CDN domains.
export const KNOWN_PUBLISHERS = [
  {
    name: "Google",
    domains: ["google.com", "gstatic.com", "googleusercontent.com", "dl.google.com", "gvt1.com", "chrome.com"]
  },
  {
    name: "Anthropic / Claude",
    domains: ["anthropic.com", "claude.ai", "claude.site", "claude.usercontent.com"]
  },
  {
    name: "OpenAI",
    domains: ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"]
  },
  {
    name: "Microsoft",
    domains: ["microsoft.com", "live.com", "office.com", "windows.com", "officecdn.microsoft.com", "azureedge.net", "visualstudio.com", "github.com", "githubusercontent.com"]
  },
  {
    name: "Mozilla",
    domains: ["mozilla.org", "mozilla.com", "download-installer.cdn.mozilla.net"]
  },
  {
    name: "Adobe",
    domains: ["adobe.com", "adobe.io", "adobelogin.com"]
  },
  {
    name: "Cloudflare",
    domains: ["cloudflare.com", "cdnjs.cloudflare.com", "workers.dev"]
  },
  {
    name: "HuggingFace",
    domains: ["huggingface.co", "hf.space"]
  },
  {
    name: "Vercel",
    domains: ["vercel.com", "vercel.app"]
  },
  {
    name: "Supabase",
    domains: ["supabase.com", "supabase.co"]
  },
  {
    name: "Zoom",
    domains: ["zoom.us", "zoom.com"]
  },
  {
    name: "Slack",
    domains: ["slack.com", "slack-edge.com"]
  },
  {
    name: "Discord",
    domains: ["discord.com", "discordapp.com", "discord.gg"]
  },
  {
    name: "GitHub",
    domains: ["github.com", "githubusercontent.com", "objects.githubusercontent.com", "github.io"]
  },
  {
    name: "Notion",
    domains: ["notion.so", "notion.site"]
  },
  {
    name: "VideoLAN (VLC)",
    domains: ["videolan.org"]
  },
  {
    name: "7-Zip",
    domains: ["7-zip.org"]
  },
  {
    name: "Apple",
    domains: ["apple.com", "cdn-apple.com", "icloud.com"]
  },
  {
    name: "Python Software Foundation",
    domains: ["python.org", "pypi.org"]
  },
  {
    name: "Node.js Foundation",
    domains: ["nodejs.org"]
  },
  {
    name: "JetBrains",
    domains: ["jetbrains.com"]
  },
  {
    name: "Brave",
    domains: ["brave.com", "laptop-updates.brave.com"]
  },
  {
    name: "Notepad++",
    domains: ["notepad-plus-plus.org"]
  }
];

export const VULNERABILITY_DEFINITIONS = {
  NO_HTTPS: {
    title: "Insecure Protocol (HTTP)",
    threatLevel: "Critical",
    levelCode: 4,
    owaspCategory: "A02:2021 - Cryptographic Failures",
    unethicalHarm: "Attainable Man-in-the-Middle (MitM) exploitation: Attackers on local/public Wi-Fi networks can eavesdrop, intercept unencrypted data, inject malicious executable code, or spoof download files directly."
  },
  MISSING_HSTS: {
    title: "Missing Strict-Transport-Security (HSTS)",
    threatLevel: "High",
    levelCode: 3,
    owaspCategory: "A05:2021 - Security Misconfiguration",
    unethicalHarm: "SSL Strip Attacks: Attackers can force encrypted connections to drop down to unencrypted HTTP, allowing session hijacking, credential theft, or silent redirecting to malware mirrors."
  },
  WEAK_HSTS: {
    title: "Weak HSTS Policy (Short max-age or no includeSubDomains)",
    threatLevel: "Medium",
    levelCode: 2,
    owaspCategory: "A05:2021 - Security Misconfiguration",
    unethicalHarm: "Subdomain SSL Strip: Short cache duration or missing subdomain enforcement leaves subdomains vulnerable to HTTP downgrade attacks."
  },
  MISSING_CSP: {
    title: "Missing Content-Security-Policy (CSP)",
    threatLevel: "High",
    levelCode: 3,
    owaspCategory: "A03:2021 - Injection (XSS)",
    unethicalHarm: "Cross-Site Scripting (XSS) Vulnerability: Without a restrictive CSP, attackers who find any input reflection can execute arbitrary JavaScript in the victim's session to steal cookies, tokens, or trigger unauthorized user actions."
  },
  WEAK_CSP: {
    title: "Weak Content-Security-Policy (unsafe-inline / unsafe-eval)",
    threatLevel: "Medium",
    levelCode: 2,
    owaspCategory: "A03:2021 - Injection (XSS)",
    unethicalHarm: "Bypassable Script Sandbox: Allowing unsafe-inline or unsafe-eval enables attackers to execute injected inline scripts despite CSP presence."
  },
  PERMISSIVE_CORS: {
    title: "Permissive CORS Policy (Wildcard Access)",
    threatLevel: "High",
    levelCode: 3,
    owaspCategory: "A01:2021 - Broken Access Control",
    unethicalHarm: "Cross-Domain Data Exfiltration: Malicious third-party websites visited in another tab can make authenticated API requests to read sensitive victim data from this site."
  },
  MISSING_CLICKJACKING_PROTECTION: {
    title: "Missing X-Frame-Options / Clickjacking Protection",
    threatLevel: "Medium",
    levelCode: 2,
    owaspCategory: "A04:2021 - Insecure Design",
    unethicalHarm: "UI Redirection & Clickjacking: Attackers can embed this website inside an invisible iframe on a phishing page and trick users into clicking buttons (e.g. confirming transfers or permissions)."
  },
  MISSING_MIME_PROTECTION: {
    title: "Missing X-Content-Type-Options (nosniff)",
    threatLevel: "Medium",
    levelCode: 2,
    owaspCategory: "A05:2021 - Security Misconfiguration",
    unethicalHarm: "MIME Sniffing Exploitation: Browsers may attempt to guess file content-types, allowing executable code disguised as benign images or text files to run."
  },
  TYPOSQUATTING_RISK: {
    title: "Suspected Typosquatting / Domain Spoofing",
    threatLevel: "Critical",
    levelCode: 4,
    owaspCategory: "A07:2021 - Identification & Authentication Failures",
    unethicalHarm: "Phishing & Malware Delivery: The domain closely mimics a legitimate brand name. Users are likely being deceived into downloading malicious payloads disguised as official software."
  },
  SUSPICIOUS_TLD: {
    title: "High-Risk Top-Level Domain (TLD)",
    threatLevel: "Medium",
    levelCode: 2,
    owaspCategory: "A05:2021 - Security Misconfiguration",
    unethicalHarm: "Abused Domain Infrastructure: TLDs with cheap or unverified registration frequently host short-lived malware distribution centers or scam campaigns."
  }
};


// Endpoints for external intelligence. All calls are made from background.js
// so API keys never touch the popup UI thread.
export const ENDPOINTS = {
  virusTotalUrlReport: "https://www.virustotal.com/api/v3/urls",
  virusTotalFileReport: "https://www.virustotal.com/api/v3/files",
  safeBrowsing: "https://safebrowsing.googleapis.com/v4/threatMatches:find",
  nvdCves: "https://services.nvd.nist.gov/rest/json/cves/2.0"
};

export const CACHE_TTL_MS = {
  virusTotal: 1000 * 60 * 60 * 6,   // 6 hours
  safeBrowsing: 1000 * 60 * 60 * 6, // 6 hours
  nvd: 1000 * 60 * 60 * 24          // 24 hours
};

export const MAX_HISTORY_ITEMS = 200;
