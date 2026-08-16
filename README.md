# 🔍 JSHound

<p align="center">
  <img src="assets/preview.png?v=2" alt="JSHound Web Dashboard Preview" width="100%">
</p>

<p align="center">
  <a href="https://github.com/rizko-d/jshound/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Architecture-Zero--Dependency-00e676?style=for-the-badge" alt="Zero-Dependency">
  <img src="https://img.shields.io/badge/OWASP-Top%2010%20(2021)-orange?style=for-the-badge" alt="OWASP Top 10">
</p>

---

## 🚀 Overview

Modern Single Page Applications (React, Next.js, Vue, Angular, Vite, Webpack) frequently leak sensitive attack surface elements in their client-side bundles. **JSHound** crawls target web applications, discovers referenced JavaScript bundles and dynamic chunks, extracts REST/GraphQL endpoints and hardcoded credentials, and automatically unpacks exposed Source Maps (`.js.map`) to recover original source code.

Equipped with both a zero-dependency **Dark-Themed Web Dashboard** and a powerful **CLI Engine**.

---

## 🎯 OWASP & MITRE ATT&CK Mapping

* **OWASP Top 10 (2021):**
  * `A01:2021 – Broken Access Control` (Discovers hidden administrative & internal API endpoints).
  * `A05:2021 – Security Misconfiguration` (Exposed `.js.map` source maps & staging environments).
  * `A07:2021 – Identification and Authentication Failures` (Hardcoded API keys, JWT tokens, credentials, AWS keys).
* **MITRE ATT&CK (Enterprise):**
  * `T1596 - Search Open Technical Databases` (Reconnaissance)
  * `T1552 - Unsecured Credentials: Credentials in Files` (Credential Access)
  * `T1592 - Gather Victim Host Information` (Reconnaissance)

---

## ✨ Key Features

- **⚡ Zero External Dependencies:** Built entirely with standard Python libraries (`urllib`, `http.server`, `re`, `json`, `argparse`). No heavy frameworks or package installations needed.
- **🖥️ Sleek Web Recon Dashboard:** Responsive dark aesthetic (`#0a0c10`, `#39d0ff`, `#00e676`) with live stats, search tabs, and scan controls.
- **🧩 Deep SPA Chunk Discovery:** Detects standard `<script>` tags as well as dynamic webpack/vite/next.js chunks (`static/chunks/...`).
- **🗺️ Source Map Unpacker:** Automatically detects and reconstructs original source file trees from `.js.map` (`sourcesContent`).
- **🔑 High-Signal Secret & Credential Scanning:**
  * Generic Key & Password Assignments (`password = "..."`, `apikey: "..."`, `secret: "..."`)
  * AWS Access Key IDs (`AKIA...`, `ASIA...`)
  * Google API / Firebase Keys (`AIza...`)
  * JSON Web Tokens (`JWT`)
  * Stripe API Keys (`pk_live...`, `pk_test...`)
  * Slack Webhooks & Tokens
  * GitHub Personal Access Tokens
  * Mailgun, SendGrid, and Square Keys
  * Private Keys & Generic Bearer tokens
- **📝 Endpoint Wordlist Generator:** Exports deduplicated endpoints for directory bruteforcing (ffuf, gobuster, burp).
- **🏢 Internal / Staging Host Discovery:** Flags `.internal`, `.staging.`, `.dev.`, and RFC1918 private IP ranges (`10.x`, `172.16.x`, `192.168.x`).
- **📊 Multi-Format Export:** Web visualizer, terminal colored summary, structured `JSON`, plain `endpoints.txt`, and executive `Markdown` reports.

---

## 💻 Usage

### 1. Interactive Web Dashboard (Recommended)
Launch the visual dashboard on `http://127.0.0.1:8899/`:
```bash
python jshound.py --web
# or simply without args:
python jshound.py
```

### 2. Online CLI Scan (Direct URL)
```bash
python jshound.py -u https://target.com/
```

With custom headers (e.g. Authenticated session / Bearer Token):
```bash
python jshound.py -u https://target.com/ -H "Authorization: Bearer <TOKEN>" -H "Cookie: session=xyz"
```

### 3. Offline / Local Directory Scan
Scan downloaded JS bundles, Electron apps, or unpacked APK assets:
```bash
python jshound.py -f ./downloaded_assets/ -o ./report_output
```

### 4. CLI Options
```text
options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target webpage URL or direct .js file URL
  -f FILE, --file FILE  Local JS file or directory to scan offline
  -w, --web             Launch interactive Dark-themed Web Dashboard
  -p PORT, --port PORT  Port for web dashboard (default: 8899)
  --no-browser          Do not open browser automatically when running in web mode
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Directory to save output reports and unpacked source maps (default: ./output)
  --no-sourcemap        Disable automatic sourcemap (.map) detection and unpacking
  --timeout TIMEOUT     HTTP request timeout in seconds (default: 12)
  -k, --insecure        Allow insecure SSL connections
  -H HEADER, --header HEADER
                        Custom HTTP header (format: 'Key: Value'). Can be repeated.
```

---

## 📁 Output Structure

When scanning a target, JSHound generates:
```text
output/
├── jshound_results.json          # Complete structured JSON dataset
├── endpoints.txt                 # Clean wordlist of discovered API endpoints & paths
├── recon_report.md               # Ready-to-use pentest findings report
└── unpacked_sourcemaps/          # Reconstructed original source codes (if .map exists)
    └── bundle.min/
        ├── src/config/aws.ts
        └── src/services/api.ts
```

---

## ⚖️ Disclaimer
*This tool is developed for authorized security research, penetration testing, and defensive auditing purposes only.*
