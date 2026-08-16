# JSHound

<p align="center">
  <img src="assets/preview.png?v=3" alt="JSHound Web Dashboard Preview" width="100%">
</p>

<p align="center">
  <a href="https://github.com/rizko-d/jshound/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Architecture-Zero--Dependency-00e676?style=for-the-badge" alt="Zero-Dependency">
  <img src="https://img.shields.io/badge/OWASP-Top%2010%20(2025)-orange?style=for-the-badge" alt="OWASP Top 10 (2025)">
  <img src="https://img.shields.io/badge/Interoperability-Postman%20%7C%20OpenAPI-9c27b0?style=for-the-badge" alt="Postman & OpenAPI">
</p>

---

## Overview

**JSHound** is a zero-dependency frontend JavaScript static reconnaissance, DOM vulnerability auditing, and multi-cloud secret hunting engine. It analyzes modern Single Page Application client-side bundles (React, Next.js, Vue, Angular, Vite, Webpack) to discover hidden attack surfaces, unpack source maps, extract API blueprints, and detect client-side vulnerabilities.

Equipped with both a zero-dependency **Dark-Themed Web Dashboard** and a scriptable **CLI Engine with Continuous Diffing**.

---

## OWASP & MITRE ATT&CK Mapping

* **OWASP Top 10 (2025 Release):**
  * `A01:2025 – Broken Access Control` (Discovers hidden administrative endpoints, IDOR surface, and API parameters).
  * `A02:2025 – Security Misconfiguration` (Exposed `.js.map` source maps, staging environments, open cloud storage endpoints).
  * `A03:2025 – Software Supply Chain Failures` (Unpacked vendor chunk inspection and third-party library reconnaissance).
  * `A05:2025 – Injection` (Detects DOM-based Cross-Site Scripting sinks and unsafe string evaluations).
  * `A07:2025 – Authentication Failures` (Hardcoded multi-cloud access keys, JWT tokens, OAuth tokens).
* **MITRE ATT&CK (Enterprise):**
  * `T1596 - Search Open Technical Databases` (Reconnaissance)
  * `T1552 - Unsecured Credentials: Credentials in Files` (Credential Access)
  * `T1592 - Gather Victim Host Information` (Reconnaissance)
  * `T1059.007 - Command and Scripting Interpreter: JavaScript` (Execution)

---

## Key Capabilities

### 1. DOM XSS & Dangerous Sink Hunter
Identifies insecure client-side source-to-sink dataflows:
* **Sinks:** `innerHTML`, `outerHTML`, `document.write`, `eval()`, `setTimeout(string)`, `dangerouslySetInnerHTML`.
* **Open Redirects:** Unvalidated `location.href`, `location.replace`, `location.assign` assignments.
* **Insecure Messaging:** `postMessage` with wildcard (`*`) target origin or message listeners lacking `origin` verification.

### 2. GraphQL Query & Mutation Extractor
Automatically extracts inline `gql` template literals and GraphQL documents (`query`, `mutation`, `subscription`) to reconstruct schemas and speed up GraphQL API fuzzing.

### 3. API Parameter & Request Blueprint Engine
Parses `fetch()`, `axios()`, and `$.ajax()` calls to extract HTTP methods (`GET`, `POST`, `PUT`, `DELETE`), URL query parameters (`?limit=&status=`), and request payloads.

### 4. Shannon Entropy Secret Heuristic
Uses mathematical Shannon Entropy calculations (`H >= 4.5`) to uncover high-randomness custom API keys and signatures that do not follow standard vendor regex patterns.

### 5. Postman v2.1 & OpenAPI 3.0 Exporters
Exports discovered attack surfaces directly into standard **Postman Collection v2.1** and **OpenAPI 3.0 Specification** JSON files for seamless importing into **Burp Suite**, **Caido**, or **Postman**.

### 6. Continuous Asset Diffing (`--diff`)
Compares new scans against historical baselines to immediately flag newly deployed endpoints, newly leaked credentials, or fresh DOM vulnerabilities in CI/CD or bug bounty monitoring.

---

## Multi-Cloud Credential Detection

* **AWS:** Access Key IDs (`AKIA...`, `ASIA...`)
* **Microsoft Azure:** Storage Account Connection Strings, Shared Access Signature (SAS) tokens (`sig=...`), Tenant / Client IDs (GUID).
* **Oracle Cloud (OCI):** User/Tenancy OCIDs (`ocid1.user...`, `ocid1.tenancy...`), OCI Private RSA Keys.
* **Google Cloud:** API Keys & Firebase Web Config (`AIza...`).
* **SaaS & Authentication:** JWTs, Stripe standard/live keys, Slack Webhooks, GitHub Tokens (`ghp_...`), Mailgun, SendGrid, Square Tokens.

---

## Usage

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

### 3. Continuous Diffing Mode (Monitoring)
Compare a fresh scan against an older baseline:
```bash
python jshound.py -u https://target.com/ --diff output/previous_scan.json
```

### 4. Offline / Local Directory Scan
Scan downloaded JS bundles, Electron apps, or unpacked APK assets:
```bash
python jshound.py -f ./downloaded_assets/ -o ./report_output
```

### 5. CLI Options
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
  --timeout TIMEOUT     HTTP request timeout in seconds (default: 15)
  -k, --insecure        Allow insecure SSL connections
  -H HEADER, --header HEADER
                        Custom HTTP header (format: 'Key: Value'). Can be repeated.
  --entropy ENTROPY     Minimum Shannon entropy threshold for secret heuristic (default: 4.5)
  --diff DIFF           Path to historical scan JSON file to perform continuous change diffing
```

---

## Output Artifacts

When running a scan, JSHound generates complete pentest artifacts:
```text
output/
├── jshound_results.json          # Complete structured JSON dataset
├── endpoints.txt                 # Clean wordlist of discovered API endpoints & paths
├── postman_collection.json       # Ready-to-import Postman Collection v2.1
├── openapi_spec.json             # OpenAPI 3.0 API Schema blueprint
├── recon_report.md               # Executive findings report with Markdown tables
└── unpacked_sourcemaps/          # Reconstructed original source code trees
    └── bundle.min/
        ├── src/config/aws.ts
        └── src/services/api.ts
```

---

## Disclaimer
*This tool is developed for authorized security research, penetration testing, and defensive auditing purposes only.*
