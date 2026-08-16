import re
import math
from typing import Dict, List, Set, Any, Optional

def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

class JSAnalyzer:
    # High-signal regular expressions for Recon & Secret Finding
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

    # Feature 1: DOM XSS & Dangerous Sink/Source Patterns
    DOM_VULN_PATTERNS = {
        "DOM XSS (innerHTML / outerHTML)": r'(?:innerHTML|outerHTML)\s*=\s*[^;]+',
        "DOM XSS (document.write)": r'document\.write(?:ln)?\s*\([^)]+\)',
        "DOM Execution (eval / setTimeout String)": r'(?:eval|setTimeout|setInterval)\s*\(\s*[\'"`][^)]+\)',
        "React Raw HTML Injection (dangerouslySetInnerHTML)": r'dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:\s*[^}]+\}',
        "Open Redirect / URL Sink (location assignment)": r'(?:window\.|document\.)?location(?:\.href|\.replace|\.assign)?\s*=\s*(?:location\.|document\.|window\.name|[a-zA-Z0-9_]+Params|getUrlParam)[^;]+',
        "Unsafe postMessage (Wildcard Target)": r'postMessage\s*\([^,]+,\s*[\'"`]\*[\'"`]\s*\)',
        "postMessage Listener (No Origin Validation)": r'addEventListener\s*\(\s*[\'"`]message[\'"`]\s*,\s*(?:function|\([^)]*\)\s*=>)[^{]*\{(?![^}]*(?:origin\s*===|\.origin\b))'
    }

    # Feature 2: GraphQL Query & Mutation Patterns
    GRAPHQL_REGEX = re.compile(
        r'(?:gql|graphql)\s*`([^`]+)`|'
        r'[\'"`]((?:query|mutation|subscription)\s+[A-Za-z0-9_]+\s*(?:\([^)]*\))?\s*\{[^\'"`]+\})[\'"`]',
        re.IGNORECASE | re.DOTALL
    )

    # Feature 3: API Parameter & Request Blueprint Patterns
    API_CALL_REGEX = re.compile(
        r'(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|\$\.ajax|\$\.get|\$\.post)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]\s*(?:,\s*(\{.*?\})\s*)?\)',
        re.IGNORECASE | re.DOTALL
    )

    def __init__(self, min_entropy: float = 4.5):
        self.min_entropy = min_entropy
        self.compiled_secrets = {name: re.compile(pat) for name, pat in self.PATTERNS.items()}
        self.compiled_dom_vulns = {name: re.compile(pat, re.IGNORECASE) for name, pat in self.DOM_VULN_PATTERNS.items()}

    def scan(self, content: str, source_url: str = "") -> Dict[str, Any]:
        results = {
            "source": source_url,
            "secrets": [],
            "endpoints": set(),
            "internal_hosts": set(),
            "dom_vulns": [],
            "graphql_queries": [],
            "api_blueprints": []
        }

        # 1. Scan Known Regex Secrets
        known_secret_values = set()
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

                if len(matched_val.strip()) < 8:
                    continue

                start = max(0, match.start() - 35)
                end = min(len(content), match.end() + 35)
                context_snippet = content[start:end].replace("\n", " ").replace("\r", " ")

                known_secret_values.add(matched_val)
                results["secrets"].append({
                    "type": sec_name,
                    "value": matched_val,
                    "context": context_snippet.strip(),
                    "entropy": round(calculate_shannon_entropy(matched_val), 2)
                })

        # Feature 4: Shannon Entropy Secret Hunter (Detect high-randomness tokens)
        for token_match in re.finditer(r'[\'"`]([a-zA-Z0-9_\-\.]{20,80})[\'"`]', content):
            token_val = token_match.group(1)
            # Skip if already captured by regex or looks like standard words/paths/JWT
            if token_val in known_secret_values or token_val.startswith("http") or "/" in token_val or token_val.startswith("ey"):
                continue
            
            ent = calculate_shannon_entropy(token_val)
            # High entropy heuristic (> min_entropy, mix of uppercase/lowercase/numbers)
            has_upper = any(c.isupper() for c in token_val)
            has_lower = any(c.islower() for c in token_val)
            has_digit = any(c.isdigit() for c in token_val)

            if ent >= self.min_entropy and (has_upper and has_lower and has_digit):
                start = max(0, token_match.start() - 35)
                end = min(len(content), token_match.end() + 35)
                context_snippet = content[start:end].replace("\n", " ").replace("\r", " ")

                results["secrets"].append({
                    "type": f"High Entropy Token (Shannon: {ent:.2f})",
                    "value": token_val,
                    "context": context_snippet.strip(),
                    "entropy": round(ent, 2)
                })
                known_secret_values.add(token_val)

        # 2. Scan Endpoints
        for ep_regex in self.ENDPOINT_REGEX:
            for match in ep_regex.findall(content):
                ep = match.strip()
                if any(ep.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".ico", ".woff", ".woff2", ".ttf"]):
                    continue
                if len(ep) > 3 and not ep.startswith("//"):
                    results["endpoints"].add(ep)

        # 3. Scan Internal / Staging Hosts
        for match in self.INTERNAL_HOST_REGEX.finditer(content):
            results["internal_hosts"].add(match.group(0))

        # Feature 1: DOM XSS & Dangerous Sink Scan
        for vuln_name, vuln_regex in self.compiled_dom_vulns.items():
            for match in vuln_regex.finditer(content):
                matched_snippet = match.group(0).strip()
                if len(matched_snippet) > 150:
                    matched_snippet = matched_snippet[:150] + "..."
                
                results["dom_vulns"].append({
                    "type": vuln_name,
                    "code": matched_snippet,
                    "source": source_url
                })

        # Feature 2: GraphQL Queries & Mutations
        for match in self.GRAPHQL_REGEX.finditer(content):
            gql_body = match.group(1) or match.group(2)
            if gql_body:
                clean_gql = re.sub(r'\s+', ' ', gql_body).strip()
                if len(clean_gql) > 15:
                    results["graphql_queries"].append({
                        "query": clean_gql,
                        "source": source_url
                    })

        # Feature 3: API Blueprints & Request Schemas
        for match in self.API_CALL_REGEX.finditer(content):
            endpoint = match.group(1)
            options = match.group(2) if match.group(2) else ""
            
            method = "GET"
            if "method:" in options.lower():
                m_match = re.search(r'method\s*:\s*[\'"`]([A-Z]+)[\'"`]', options, re.IGNORECASE)
                if m_match:
                    method = m_match.group(1).upper()
            elif "post" in match.group(0).lower():
                method = "POST"

            params = []
            if "?" in endpoint:
                query_str = endpoint.split("?", 1)[1]
                params = [p.split("=")[0] for p in query_str.split("&") if p]

            results["api_blueprints"].append({
                "endpoint": endpoint,
                "method": method,
                "params": params,
                "source": source_url
            })

        # Convert sets to sorted lists
        results["endpoints"] = sorted(list(results["endpoints"]))
        results["internal_hosts"] = sorted(list(results["internal_hosts"]))

        return results
