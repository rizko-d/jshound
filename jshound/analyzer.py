import re
from typing import Dict, List, Set, Any

class JSAnalyzer:
    # High-signal regular expressions for Recon & Secret Finding
    PATTERNS = {
        "AWS Access Key ID": r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])', # validated by AKIA/ASIA prefix
        "Google API Key / Firebase": r'AIza[0-9A-Za-z\\-_]{35}',
        "JSON Web Token (JWT)": r'ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        "Stripe Standard / Publishable Key": r'(?:pk|sk)_(?:test|live)_[0-9a-zA-Z]{24,34}',
        "Slack Webhook / Token": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*|https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
        "GitHub Personal Access Token": r'gh[pousr]_[A-Za-z0-9_]{36,255}',
        "Generic Bearer Token": r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}',
        "Private RSA / SSH Key": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "Basic Auth in URL": r'https?://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9\.\-]+'
    }

    ENDPOINT_REGEX = [
        # REST API endpoints & paths
        re.compile(r'[\'"`](/(?:api|v[1-9]|rest|graphql|oauth|auth|user|admin|internal|v1|v2|v3|ws)/[^\'"`\s\r\n<>]+)[\'"`]', re.IGNORECASE),
        re.compile(r'[\'"`](https?://[^\'"`\s\r\n<>]+)[\'"`]', re.IGNORECASE),
        re.compile(r'[\'"`](/(?:[a-zA-Z0-9_\-\.]+)/(?:[a-zA-Z0-9_\-\.]+)(?:\?[^\'"`\s<>]*)?)[\'"`]')
    ]

    INTERNAL_HOST_REGEX = re.compile(
        r'https?://(?:[a-zA-Z0-9_\-]+\.)*(?:staging|dev|internal|corp|test|uat|local|admin|sandbox)\.[a-zA-Z0-9_\-\.]+|'
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
                matched_val = match.group(0)
                
                # Filter AWS false positives (must start with AKIA or ASIA)
                if sec_name == "AWS Access Key ID" and not (matched_val.startswith("AKIA") or matched_val.startswith("ASIA")):
                    continue

                # Filter short or dummy values
                if len(matched_val.strip()) < 8:
                    continue

                # Extract context snippet (surrounding 30 chars)
                start = max(0, match.start() - 30)
                end = min(len(content), match.end() + 30)
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
