# SecureDownload AI & Website Vulnerability Radar

A Chrome extension that answers two critical questions before you run or interact with downloaded files:
1. **"Can I trust this downloaded software/file before I open it?"**
2. **"How secure is this website, and what cybersecurity vulnerabilities does it have?"**

Unlike antivirus tools that scan *after* a file lands on disk, SecureDownload AI pauses downloads the instant they start, runs a multi-signal security pipeline, and gives you a Trust Score, Website Security Analysis, and Threat Exploit breakdown.

---

## Key Features

- **Universal File Monitoring**: Parses and checks **ALL** downloaded file types — installers (`.exe`, `.msi`, `.dmg`, `.pkg`, `.apk`), archives (`.zip`, `.7z`, `.tar`), documents (`.pdf`, `.docx`), scripts (`.js`, `.py`, `.sh`, `.ps1`), media, and code files.
- **Website Vulnerability Audit Engine**: Performs live audits on download source sites and active browser tabs:
  - **HTTPS & SSL/TLS Protocol Security**
  - **HTTP Strict Transport Security (HSTS)**
  - **Content-Security-Policy (CSP)**
  - **Cross-Origin Resource Sharing (CORS)**
  - **Clickjacking Protection (`X-Frame-Options` & `frame-ancestors`)**
  - **MIME-Sniffing Prevention (`X-Content-Type-Options: nosniff`)**
  - **Domain Typosquatting & TLD Risk Radar**
- **Unethical Harm & Exploit Scenarios**: Every detected weakness includes a clear, explicit breakdown of how malicious actors can exploit the vulnerability (e.g. Man-in-the-Middle traffic interception, XSS payload injection, Cross-Domain Data Theft, UI Clickjacking).
- **Official CDN Recognition**: Seed list of software publishers includes distribution CDNs (Google's `gvt1.com`, `dl.google.com`, Microsoft Azure CDNs, GitHub release objects, Mozilla CDNs) so legitimate software receives accurate high scores.
- **Modern Tabbed Popup Dashboard**:
  - 📥 **Download Analysis** (Trust Score gauge, factor breakdown, Resume/Delete actions)
  - 🛡️ **Web Security** (Live Website Security Score, Header Status Grid, Vulnerability Threat Cards with Exploit Harm Scenarios)
  - 📜 **Scan History** (Historical records & stats)

---

## Installation & Setup

1. Open `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** and select this directory
4. Pin the extension to your browser bar

### API Keys (Optional but Recommended)

Click the extension icon → Gear icon (⚙) → **Settings**:
- **VirusTotal API Key**: Powers the VirusTotal Reputation check.
- **Google Safe Browsing API Key**: Overrides score if URL matches Google threat database.
- **NVD API Key**: Raises rate limits for CVE vulnerability lookup.

*Note: All core features (HTTPS, domain verification, CDN correlation, website vulnerability header scanning, typosquatting checks, file type parsing) work without API keys.*

---

## Project Structure

```
manifest.json
background.js              # Download interception, pipeline & website security orchestration
modules/
  config.js                 # Publisher CDNs, file category sets, vulnerability definitions & harm scenarios
  downloadParser.js          # File parsing & category classification
  sourceVerification.js       # Website vulnerability audit engine, HSTS, CSP, CORS, XFO, typosquatting
  publisherVerification.js    # Domain & CDN publisher correlation
  fileIntegrity.js            # SHA-256 network hash check
  threatIntelligence.js        # VirusTotal & Safe Browsing integrations
  vulnerabilityIntelligence.js # NVD/CVE lookup
  trustEngine.js               # Weighted trust score algorithm
  recommendationEngine.js       # Action recommendation engine
  storageManager.js             # Local storage & scan history
  notificationEngine.js          # Desktop notifications
popup/                       # Dashboard UI (HTML, JS, CSS)
options/                     # Settings page
icons/
```
