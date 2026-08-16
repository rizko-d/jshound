# 🔍 JSHound

> **Fast Frontend JS Static Reconnaissance & Secret/Endpoint Hunter**  
> *Zero-dependency Python CLI & Web Dashboard for Offensive Security, Web Application Penetration Testing, and Bug Bounty Reconnaissance.*

---

## 🚀 Overview

Modern Single Page Applications (React, Next.js, Vue, Angular, Vite, Webpack) frequently leak sensitive attack surface elements in their client-side bundles. **JSHound** crawls target web applications, discovers referenced JavaScript bundles and dynamic chunks, extracts REST/GraphQL endpoints and hardcoded credentials, and automatically unpacks exposed Source Maps (`.js.map`) to recover original source code.

Now includes an **interactive zero-dependency Dark-Themed Web Dashboard** for visual reconnaissance.

---

## 🎯 OWASP & MITRE ATT&CK Mapping

* **OWASP Top 10 (2021):**
  * `A01:2021 – Broken Access Control` (Discovers hidden administrative & internal API endpoints).
  * `A05:2021 – Security Misconfiguration` (Exposed `.js.map` source maps & staging environments).
  * `A07:2021 – Identification and Authentication Failures` (Hardcoded API keys, JWT tokens, AWS credentials).
* **MITRE ATT&CK (Enterprise):**
  * `T1596 - Search Open Technical Databases` (Reconnaissance)
  * `T1552 - Unsecured Credentials: Credentials in Files` (Credential Access)
  * `T1592 - Gather Victim Host Information` (Reconnaissance)

---

## ✨ Features

- **Zero External Dependencies:** Runs on pure standard Python library (`urllib`, `http.server`, `re`, `json`, `argparse`).
- **Interactive Web UI:** Modern responsive dark dashboard (`#0a0c10`, `#39d0ff`, `#00e676`) with live stats, search tabs, and scan controls.
- **Deep SPA Chunk Discovery:** Detects standard `<script>` tags as well as dynamic webpack/vite/next.js chunks (`static/chunks/...`).
- **Source Map Unpacker:** Detects and reconstructs full original project trees from `.js.map` files (`sourcesContent`).
- **High-Signal Secret Scanning:**
  * AWS Access Key IDs (`AKIA...`, `ASIA...`)
  * Google API / Firebase Keys (`AIza...`)
  * JSON Web Tokens (`JWT`)
  * Stripe API Keys (`pk_live...`, `pk_test...`)
  * Slack Webhooks & Tokens
  * GitHub Personal Access Tokens
  * Private Keys & Generic Bearer tokens
- **Endpoint Wordlist Generator:** Exports deduplicated endpoints for directory bruteforcing (ffuf, gobuster, burp).
- **Internal / Staging Host Discovery:** Flags `.internal`, `.staging.`, `.dev.`, and RFC1918 private IP ranges (`10.x`, `172.16.x`, `192.168.x`).
- **Multi-Format Export:** Web visualizer, terminal colored summary, structured `JSON`, plain `endpoints.txt`, and executive `Markdown` reports.

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
