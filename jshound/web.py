import json
import os
import sys
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
from typing import Dict, Any

from jshound.crawler import JSCrawler
from jshound.analyzer import JSAnalyzer
from jshound.sourcemap import SourceMapUnpacker

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JSHound - Web Security Recon Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0c10;
            --bg-card: #12161f;
            --bg-subtle: #1a202c;
            --border-color: #242c3d;
            --text-main: #f0f6fc;
            --text-muted: #8b949e;
            --accent-cyan: #39d0ff;
            --accent-green: #00e676;
            --accent-red: #ff5252;
            --accent-orange: #ffab40;
            --font-main: 'Plus Jakarta Sans', -apple-system, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-primary);
            color: var(--text-main);
            font-family: var(--font-main);
            line-height: 1.6;
            padding: 24px;
        }

        .container {
            max-width: 1280px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 28px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .brand-logo {
            font-size: 28px;
        }

        .brand-title {
            font-size: 24px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-green));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-desc {
            font-size: 13px;
            color: var(--text-muted);
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .badge-zero-dep {
            background: rgba(0, 230, 118, 0.1);
            color: var(--accent-green);
            border: 1px solid rgba(0, 230, 118, 0.3);
            padding: 5px 12px;
            border-radius: 99px;
            font-size: 11px;
            font-family: var(--font-mono);
            font-weight: 600;
        }

        .scan-box {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 28px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.3);
        }

        .input-group {
            display: flex;
            gap: 12px;
        }

        .input-url {
            flex: 1;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px 18px;
            font-size: 15px;
            color: var(--text-main);
            font-family: var(--font-mono);
            outline: none;
            transition: all 0.2s ease;
        }

        .input-url:focus {
            border-color: var(--accent-cyan);
            box-shadow: 0 0 0 3px rgba(57, 208, 255, 0.15);
        }

        .btn-scan {
            background: linear-gradient(135deg, #00b4d8, #0077b6);
            color: #ffffff;
            border: none;
            border-radius: 8px;
            padding: 0 28px;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .btn-scan:hover {
            opacity: 0.95;
            transform: translateY(-1px);
        }

        .btn-scan:disabled {
            background: #2d3748;
            cursor: not-allowed;
            transform: none;
            opacity: 0.6;
        }

        .options-row {
            display: flex;
            gap: 20px;
            margin-top: 14px;
            font-size: 13px;
            color: var(--text-muted);
        }

        .checkbox-label {
            display: flex;
            align-items: center;
            gap: 6px;
            cursor: pointer;
            user-select: none;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 16px 20px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .stat-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            font-weight: 600;
        }

        .stat-value {
            font-size: 28px;
            font-weight: 800;
            font-family: var(--font-mono);
        }

        .stat-value.red { color: var(--accent-red); }
        .stat-value.green { color: var(--accent-green); }
        .stat-value.cyan { color: var(--accent-cyan); }
        .stat-value.orange { color: var(--accent-orange); }

        .toolbar-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 12px;
            margin-bottom: 16px;
            flex-wrap: wrap;
            gap: 12px;
        }

        .tabs {
            display: flex;
            gap: 8px;
        }

        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            padding: 8px 16px;
            font-size: 14px;
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .tab-btn:hover {
            color: var(--text-main);
            background: var(--bg-subtle);
        }

        .tab-btn.active {
            color: var(--accent-cyan);
            background: rgba(57, 208, 255, 0.1);
        }

        .report-actions {
            display: flex;
            gap: 8px;
        }

        .btn-report {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 7px 14px;
            font-size: 12px;
            font-family: var(--font-mono);
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .btn-report:hover {
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
            background: rgba(57, 208, 255, 0.05);
        }

        .btn-report:disabled {
            opacity: 0.4;
            cursor: not-allowed;
            border-color: var(--border-color);
            color: var(--text-muted);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 16px rgba(0,0,0,0.2);
        }

        .table-responsive {
            width: 100%;
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }

        th {
            background: var(--bg-subtle);
            color: var(--text-muted);
            font-weight: 600;
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
        }

        td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }

        tr:last-child td {
            border-bottom: none;
        }

        tr:hover td {
            background: rgba(255,255,255,0.015);
        }

        .mono {
            font-family: var(--font-mono);
        }

        .badge-type {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            font-family: var(--font-mono);
            background: rgba(255, 82, 82, 0.15);
            color: var(--accent-red);
            border: 1px solid rgba(255, 82, 82, 0.3);
        }

        .list-container {
            padding: 12px;
            max-height: 500px;
            overflow-y: auto;
        }

        .list-item {
            padding: 10px 14px;
            border-radius: 6px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            margin-bottom: 8px;
            font-family: var(--font-mono);
            font-size: 13px;
            word-break: break-all;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .list-item:hover {
            border-color: var(--accent-cyan);
        }

        .empty-state {
            padding: 40px;
            text-align: center;
            color: var(--text-muted);
            font-size: 14px;
        }

        .spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 0.8s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div class="brand-logo">🔍</div>
                <div>
                    <div class="brand-title">JSHound</div>
                    <div class="brand-desc">Fast Frontend JS Static Reconnaissance & Secret/Endpoint Hunter</div>
                </div>
            </div>
            <div class="header-actions">
                <span class="badge-zero-dep">⚡ Zero-Dep Architecture</span>
            </div>
        </header>

        <div class="scan-box">
            <form id="scanForm" onsubmit="startScan(event)">
                <div class="input-group">
                    <input type="text" id="targetUrl" class="input-url" placeholder="Enter target URL (e.g. https://ginandjuice.shop/ or http://localhost:3000)" required autocomplete="off" />
                    <button type="submit" id="btnScan" class="btn-scan">
                        <span id="btnText">Launch Recon</span>
                        <span id="btnSpinner" class="spinner" style="display: none;"></span>
                    </button>
                </div>
                <div class="options-row">
                    <label class="checkbox-label">
                        <input type="checkbox" id="chkSourcemap" checked />
                        Auto Unpack Source Maps (.js.map)
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="chkInsecure" />
                        Allow Insecure SSL
                    </label>
                </div>
            </form>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Files Analyzed</div>
                <div class="stat-value cyan" id="statFiles">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Secrets Discovered</div>
                <div class="stat-value red" id="statSecrets">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Unique Endpoints</div>
                <div class="stat-value green" id="statEndpoints">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Internal / Staging Hosts</div>
                <div class="stat-value orange" id="statHosts">0</div>
            </div>
        </div>

        <div class="toolbar-row">
            <div class="tabs">
                <button class="tab-btn active" onclick="switchTab('secrets', this)">🔑 Exposed Secrets (<span id="countSecrets">0</span>)</button>
                <button class="tab-btn" onclick="switchTab('endpoints', this)">🌐 API Endpoints (<span id="countEndpoints">0</span>)</button>
                <button class="tab-btn" onclick="switchTab('hosts', this)">🏢 Internal Hosts (<span id="countHosts">0</span>)</button>
                <button class="tab-btn" onclick="switchTab('files', this)">📦 Analyzed Files (<span id="countFiles">0</span>)</button>
            </div>

            <div class="report-actions">
                <button id="btnExportMd" class="btn-report" onclick="downloadMarkdown()" disabled>
                    <span>📄 Export Markdown</span>
                </button>
                <button id="btnExportJson" class="btn-report" onclick="downloadJSON()" disabled>
                    <span>💾 Export JSON</span>
                </button>
                <button id="btnExportTxt" class="btn-report" onclick="downloadEndpointsTxt()" disabled>
                    <span>📝 Endpoints .txt</span>
                </button>
            </div>
        </div>

        <!-- TAB: SECRETS -->
        <div id="tab-secrets" class="tab-content active">
            <div class="card">
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 220px;">Type</th>
                                <th>Detected Value</th>
                                <th>Source Location</th>
                                <th>Context Snippet</th>
                            </tr>
                        </thead>
                        <tbody id="secretsTableBody">
                            <tr><td colspan="4" class="empty-state">No scan executed yet. Enter a URL above to start.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB: ENDPOINTS -->
        <div id="tab-endpoints" class="tab-content">
            <div class="card">
                <div class="list-container" id="endpointsList">
                    <div class="empty-state">No endpoints discovered yet.</div>
                </div>
            </div>
        </div>

        <!-- TAB: HOSTS -->
        <div id="tab-hosts" class="tab-content">
            <div class="card">
                <div class="list-container" id="hostsList">
                    <div class="empty-state">No internal / staging hosts found.</div>
                </div>
            </div>
        </div>

        <!-- TAB: FILES -->
        <div id="tab-files" class="tab-content">
            <div class="card">
                <div class="list-container" id="filesList">
                    <div class="empty-state">No JS bundles analyzed yet.</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentScanResult = null;

        function switchTab(tabName, element) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            element.classList.add('active');
            document.getElementById('tab-' + tabName).classList.add('active');
        }

        async function startScan(e) {
            e.preventDefault();
            const urlInput = document.getElementById('targetUrl').value.trim();
            const chkSourcemap = document.getElementById('chkSourcemap').checked;
            const chkInsecure = document.getElementById('chkInsecure').checked;

            if (!urlInput) return;

            const btnScan = document.getElementById('btnScan');
            const btnText = document.getElementById('btnText');
            const btnSpinner = document.getElementById('btnSpinner');

            btnScan.disabled = true;
            btnText.innerText = "Scanning Assets...";
            btnSpinner.style.display = "inline-block";

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        url: urlInput,
                        unpack_sourcemap: chkSourcemap,
                        insecure: chkInsecure
                    })
                });

                const data = await response.json();
                if (data.error) {
                    alert('Scan Notice: ' + data.error);
                } else {
                    currentScanResult = data;
                    renderResults(data);
                    enableReportButtons(true);
                }
            } catch (err) {
                alert('Request failed: ' + err.message);
            } finally {
                btnScan.disabled = false;
                btnText.innerText = "Launch Recon";
                btnSpinner.style.display = "none";
            }
        }

        function enableReportButtons(enabled) {
            document.getElementById('btnExportMd').disabled = !enabled;
            document.getElementById('btnExportJson').disabled = !enabled;
            document.getElementById('btnExportTxt').disabled = !enabled;
        }

        function renderResults(data) {
            const files = data.files_analyzed || [];
            const secrets = data.secrets || [];
            const endpoints = data.endpoints || [];
            const hosts = data.internal_hosts || [];

            // Stats Update
            document.getElementById('statFiles').innerText = files.length;
            document.getElementById('statSecrets').innerText = secrets.length;
            document.getElementById('statEndpoints').innerText = endpoints.length;
            document.getElementById('statHosts').innerText = hosts.length;

            document.getElementById('countFiles').innerText = files.length;
            document.getElementById('countSecrets').innerText = secrets.length;
            document.getElementById('countEndpoints').innerText = endpoints.length;
            document.getElementById('countHosts').innerText = hosts.length;

            // 1. Secrets Table
            const secretsBody = document.getElementById('secretsTableBody');
            if (secrets.length === 0) {
                secretsBody.innerHTML = '<tr><td colspan="4" class="empty-state">No secrets or credentials found.</td></tr>';
            } else {
                secretsBody.innerHTML = secrets.map(s => `
                    <tr>
                        <td><span class="badge-type">${escapeHtml(s.type)}</span></td>
                        <td class="mono" style="color: var(--accent-red); font-weight: 600;">${escapeHtml(s.value)}</td>
                        <td class="mono" style="color: var(--text-muted);">${escapeHtml(s.source)}</td>
                        <td class="mono" style="font-size: 12px; color: var(--text-muted);">${escapeHtml(s.context || '')}</td>
                    </tr>
                `).join('');
            }

            // 2. Endpoints List
            const endpointsList = document.getElementById('endpointsList');
            if (endpoints.length === 0) {
                endpointsList.innerHTML = '<div class="empty-state">No endpoints discovered.</div>';
            } else {
                endpointsList.innerHTML = endpoints.map(ep => `
                    <div class="list-item">
                        <span>${escapeHtml(ep)}</span>
                    </div>
                `).join('');
            }

            // 3. Hosts List
            const hostsList = document.getElementById('hostsList');
            if (hosts.length === 0) {
                hostsList.innerHTML = '<div class="empty-state">No internal hosts discovered.</div>';
            } else {
                hostsList.innerHTML = hosts.map(h => `
                    <div class="list-item" style="color: var(--accent-orange);">
                        <span>${escapeHtml(h)}</span>
                    </div>
                `).join('');
            }

            // 4. Files List
            const filesList = document.getElementById('filesList');
            if (files.length === 0) {
                filesList.innerHTML = '<div class="empty-state">No JS files analyzed.</div>';
            } else {
                filesList.innerHTML = files.map(f => `
                    <div class="list-item" style="color: var(--accent-cyan);">
                        <span>${escapeHtml(f)}</span>
                    </div>
                `).join('');
            }
        }

        function downloadFile(filename, content, mimeType) {
            const blob = new Blob([content], { type: mimeType });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }

        function downloadJSON() {
            if (!currentScanResult) return;
            const targetDomain = getSafeFilename(currentScanResult.target || 'target');
            downloadFile(`jshound_${targetDomain}.json`, JSON.stringify(currentScanResult, null, 2), 'application/json');
        }

        function downloadEndpointsTxt() {
            if (!currentScanResult) return;
            const targetDomain = getSafeFilename(currentScanResult.target || 'target');
            const content = (currentScanResult.endpoints || []).join('\\n');
            downloadFile(`endpoints_${targetDomain}.txt`, content, 'text/plain');
        }

        function downloadMarkdown() {
            if (!currentScanResult) return;
            const data = currentScanResult;
            const targetDomain = getSafeFilename(data.target || 'target');

            let md = `# 🛡️ JSHound Security Reconnaissance Report\\n\\n`;
            md += `**Target URL:** \`${data.target}\`  \\n`;
            md += `**Analyzed Files:** \`${(data.files_analyzed || []).length}\`  \\n`;
            md += `**Source Maps Extracted:** \`${(data.sourcemaps_unpacked || []).length}\`  \\n\\n`;
            md += `---\\n\\n## 1. 🔑 Exposed Secrets & API Tokens (${(data.secrets || []).length})\\n\\n`;
            md += `| Type | Value | Source File |\\n| :--- | :--- | :--- |\\n`;
            
            (data.secrets || []).forEach(s => {
                md += `| **${s.type}** | \`${s.value}\` | \`${s.source}\` |\\n`;
            });

            md += `\\n---\\n\\n## 2. 🏢 Internal & Staging Hosts (${(data.internal_hosts || []).length})\\n\\n`;
            (data.internal_hosts || []).forEach(h => {
                md += `- \`${h}\`\\n`;
            });

            md += `\\n---\\n\\n## 3. 🌐 Discovered Endpoints & Paths (${(data.endpoints || []).length})\\n\\n\`\`\`text\\n`;
            (data.endpoints || []).forEach(ep => {
                md += `${ep}\\n`;
            });
            md += `\`\`\`\\n`;

            downloadFile(`recon_report_${targetDomain}.md`, md, 'text/markdown');
        }

        function getSafeFilename(url) {
            return url.replace(/https?:\\/\\//g, '').replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 30);
        }

        function escapeHtml(text) {
            if (!text) return '';
            const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
            return text.replace(/[&<>"']/g, m => map[m]);
        }
    </script>
</body>
</html>
"""

class JSHoundRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Clean terminal logging
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/scan":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len)
            try:
                data = json.loads(post_body.decode("utf-8"))
                target_url = data.get("url", "").strip()
                unpack_map = data.get("unpack_sourcemap", True)
                insecure = data.get("insecure", False)

                if not target_url:
                    self._send_json({"error": "Target URL is required"}, 400)
                    return

                if not target_url.startswith("http://") and not target_url.startswith("https://"):
                    target_url = "https://" + target_url

                # Perform scan
                result = self._run_scan(target_url, unpack_sourcemap=unpack_map, insecure=insecure)
                self._send_json(result, 200)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def _send_json(self, payload: Dict[str, Any], status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def _run_scan(self, target_url: str, unpack_sourcemap: bool = True, insecure: bool = False) -> Dict[str, Any]:
        crawler = JSCrawler(timeout=15, verify_ssl=not insecure)
        analyzer = JSAnalyzer()
        unpacker = SourceMapUnpacker()

        aggregated: Dict[str, Any] = {
            "target": target_url,
            "files_analyzed": [],
            "sourcemaps_unpacked": [],
            "secrets": [],
            "endpoints": set(),
            "internal_hosts": set()
        }

        initial_content, err = crawler.fetch_url(target_url)
        if not initial_content:
            return {"error": f"Failed to fetch {target_url}. Reason: {err}"}

        if target_url.split("?")[0].endswith(".js"):
            js_urls = [target_url]
        else:
            js_urls = crawler.extract_js_links(target_url, initial_content)
            html_scan = analyzer.scan(initial_content, source_url=target_url + " (inline)")
            for s in html_scan["secrets"]:
                s["source"] = target_url + " (inline)"
                aggregated["secrets"].append(s)
            aggregated["endpoints"].update(html_scan["endpoints"])
            aggregated["internal_hosts"].update(html_scan["internal_hosts"])

        for js_url in js_urls:
            js_content, _ = crawler.fetch_url(js_url)
            if not js_content:
                continue

            aggregated["files_analyzed"].append(js_url)
            scan_res = analyzer.scan(js_content, source_url=js_url)
            for s in scan_res["secrets"]:
                s["source"] = js_url
                aggregated["secrets"].append(s)
            aggregated["endpoints"].update(scan_res["endpoints"])
            aggregated["internal_hosts"].update(scan_res["internal_hosts"])

            if unpack_sourcemap:
                map_url = unpacker.detect_map_url(js_url, js_content)
                if map_url:
                    map_content, _ = crawler.fetch_url(map_url)
                    if map_content:
                        target_dir = os.path.join("output", "unpacked_sourcemaps", os.path.basename(js_url).replace(".js", ""))
                        count, files = unpacker.unpack(map_content, target_dir)
                        if count > 0:
                            aggregated["sourcemaps_unpacked"].append({
                                "map_url": map_url,
                                "unpacked_count": count,
                                "dest_dir": target_dir
                            })
                            for extracted_f in files:
                                full_p = os.path.join(target_dir, extracted_f)
                                try:
                                    with open(full_p, "r", encoding="utf-8", errors="ignore") as ef:
                                        src_code = ef.read()
                                        src_scan = analyzer.scan(src_code, source_url=extracted_f)
                                        for s in src_scan["secrets"]:
                                            s["source"] = f"[SourceMap] {extracted_f}"
                                            aggregated["secrets"].append(s)
                                        aggregated["endpoints"].update(src_scan["endpoints"])
                                        aggregated["internal_hosts"].update(src_scan["internal_hosts"])
                                except Exception:
                                    pass

        aggregated["endpoints"] = sorted(list(aggregated["endpoints"]))
        aggregated["internal_hosts"] = sorted(list(aggregated["internal_hosts"]))
        return aggregated

def start_web_server(host: str = "127.0.0.1", port: int = 8899, auto_open: bool = True):
    server = HTTPServer((host, port), JSHoundRequestHandler)
    url = f"http://{host}:{port}/"
    print(f"\033[92m[✓] JSHound Web Dashboard live at: {url}\033[0m")
    print(f"\033[90m[*] Press Ctrl+C to stop the web server.\033[0m\n")

    if auto_open:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\033[93m[*] Stopping JSHound Web Server...\033[0m")
        server.server_close()
