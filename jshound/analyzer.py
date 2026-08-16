import re
from typing import Dict, List, Set, Any

class JSAnalyzer:
    # High-signal regular expressions for Recon & Secret Finding (AWS, Azure, OCI, GCP, Saas)
    PATTERNS = {
        # --- Multi-Cloud Credentials ---
        "AWS Access Key ID": r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])',
        "Azure Shared Access Signature (SAS) Token": r'(?i)sig=[a-zA-Z0-9%_\-]{40,}',
        "Azure Storage Account Connection String": r'DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]{3,24};AccountKey=[a-zA-Z0-9+/=]{64,88};',
        "Azure Tenant / Client ID (GUID)": r'(?i)(?:tenant_?id|client_?id|subscription_?id)\s*[:=]\s*[\'"`]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\'"`]',
        "Oracle Cloud (OCI) OCID Resource ID": r'ocid1\.[a-z0-9\-]+\.[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.[a-z0-9]{20,}',
        "Oracle Cloud (OCI) User/Tenancy OCID": r'ocid1\.(?:user|tenancy|instance|compartment|volume|vcn|subnet|key)\.oc1\.[a-z0-9\-_]*\.[a-z0-9]{20,}',
        "Oracle Cloud (OCI) Private Key": r'-----BEGIN (?:RSA )?PRIVATE KEY-----[a-zA-Z0-9+/=\s\r\n]+-----END (?:RSA )?PRIVATE KEY-----',
        "Google API Key / Firebase": r'AIza[0-9A-Za-z\\-_]{35}',

        # --- Tokens & API Keys ---
        "JSON Web Token (JWT)": r'ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        "Stripe Standard / Publishable Key": r'(?:pk|sk)_(?:test|live)_[0-9a-zA-Z]{24,34}',
        "Slack Webhook / Token": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*|https://hooks\.slack\.(?:com|example\.com)/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
        "GitHub Personal Access Token": r'gh[pousr]_[A-Za-z0-9_]{36,255}',
        "Generic Secret / API Key Assignment": r'(?i)(?:api_key|apikey|secret_key|app_secret|client_secret|access_token|auth_token|password|private_key)\s*[:=]\s*[\'"`]([^\'"`\s]{8,120})[\'"`]',
        "Generic Bearer Token": r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}',
        "Private RSA / SSH Key": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "Basic Auth in URL": r'https?://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9\.\-]+',
        "Mailgun API Key": r'key-[0-9a-zA-Z]{32}',
        "Square Access Token / App ID": r'sq0atp-[0-9A-Za-z\-_]{22}|sq0idp-[0-9A-Za-z\-_]{22}',
        "SendGrid API Key": r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}'
    }

    ENDPOINT_REGEX = [
        # REST API endpoints & paths
        re.compile(r'[\'"`](/(?:api|v[1-9]|rest|graphql|oauth|auth|user|admin|internal|v1|v2|v3|ws|challenges|address|basket|products|feedback|wallet)/[^\'"`\s\r\n<>]+)[\'"`]', re.IGNORECASE),
        re.compile(r'[\'"`](https?://[^\'"`\s\r\n<>]+)[\'"`]', re.IGNORECASE),
        re.compile(r'[\'"`](/(?:[a-zA-Z0-9_\-\.]+)/(?:[a-zA-Z0-9_\-\.]+)(?:\?[^\'"`\s<>]*)?)[\'"`]')
    ]

    INTERNAL_HOST_REGEX = re.compile(
        r'https?://(?:[a-zA-Z0-9_\-]+\.)*(?:staging|dev|internal|corp|test|uat|local|admin|sandbox|blob\.core\.windows\.net|oraclecloud\.com)\.[a-zA-Z0-9_\-\.]+|'
        r'https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost)(?::\d+)?',
        re.IGNORECASE
    )

    def __init__(self):
        self.compiled_secrets = {name: re.compile(pat) for name, pat in self.PATTERNS.items()}

    def scan(self, content: str, source_url: str = "") -> Dict[str, Any]:
        results = {
            "source": source_url,
            "secrets": [],
            "endpoints": set(),
            "internal_hosts": set()
        }

        # 1. Scan Secrets
        for sec_name, sec_regex in self.compiled_secrets.items():
            for match in sec_regex.finditer(content):
                if sec_name in ["Generic Secret / API Key Assignment", "Azure Tenant / Client ID (GUID)"]:
                    matched_val = match.group(1)
                else:
                    matched_val = match.group(0)
                
                # Filter AWS false positives (must start with AKIA or ASIA)
                if sec_name == "AWS Access Key ID" and not (matched_val.startswith("AKIA") or matched_val.startswith("ASIA")):
                    continue

                # Filter obvious code placeholders/generic words
                if matched_val.lower() in ["password", "username", "undefined", "true", "false", "null", "application/json", "text/plain"]:
                    continue

                # Filter short values
                if len(matched_val.strip()) < 8:
                    continue

                # Extract context snippet (surrounding 35 chars)
                start = max(0, match.start() - 35)
                end = min(len(content), match.end() + 35)
                context_snippet = content[start:end].replace("\n", " ").replace("\r", " ")

                results["secrets"].append({
                    "type": sec_name,
                    "value": matched_val,
                    "context": context_snippet.strip()
                })

        # 2. Scan Endpoints
        for ep_regex in self.ENDPOINT_REGEX:
            for match in ep_regex.findall(content):
                ep = match.strip()
                # Filter out obvious non-endpoints (image extensions, generic HTML/CSS, font files)
                if any(ep.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".ico", ".woff", ".woff2", ".ttf"]):
                    continue
                if len(ep) > 3 and not ep.startswith("//"):
                    results["endpoints"].add(ep)

        # 3. Scan Internal / Staging Hosts
        for match in self.INTERNAL_HOST_REGEX.finditer(content):
            results["internal_hosts"].add(match.group(0))

        # Convert sets to sorted lists
        results["endpoints"] = sorted(list(results["endpoints"]))
        results["internal_hosts"] = sorted(list(results["internal_hosts"]))

        return results
