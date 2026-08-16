import re
import urllib.request
import urllib.error
import urllib.parse
from typing import List, Set, Dict, Optional

class JSCrawler:
    def __init__(self, timeout: int = 10, headers: Optional[Dict[str, str]] = None, verify_ssl: bool = True):
        self.timeout = timeout
        self.headers = headers or {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "*/*"
        }
        self.verify_ssl = verify_ssl

    def fetch_url(self, url: str) -> Optional[str]:
        try:
            req = urllib.request.Request(url, headers=self.headers)
            # Create context if SSL verification should be relaxed if needed
            ctx = None
            if not self.verify_ssl:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as response:
                content_type = response.headers.get("Content-Type", "")
                data = response.read()
                try:
                    return data.decode("utf-8")
                except UnicodeDecodeError:
                    return data.decode("latin-1", errors="ignore")
        except Exception as e:
            return None

    def extract_js_links(self, base_url: str, html_content: str) -> List[str]:
        found_urls: Set[str] = set()

        # 1. Standard <script src="...">
        script_pattern = re.compile(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
        for match in script_pattern.findall(html_content):
            full_url = urllib.parse.urljoin(base_url, match.strip())
            if self._is_js_candidate(full_url):
                found_urls.add(full_url)

        # 2. Modern webpack/vite/next.js dynamic chunks pattern
        # e.g., static/chunks/..., _next/static/..., /assets/index-xxx.js
        chunk_patterns = [
            re.compile(r'[\'"]([^\'"]*\.js(?:[?#][^\'"]*)?)[\'"]', re.IGNORECASE),
            re.compile(r'[\'"]([^\'"]*(?:static|chunks|assets|bundles|build)/[^\'"]+)[\'"]', re.IGNORECASE)
        ]

        for cp in chunk_patterns:
            for match in cp.findall(html_content):
                clean_match = match.strip()
                if clean_match.endswith(".js") or ".js?" in clean_match:
                    full_url = urllib.parse.urljoin(base_url, clean_match)
                    if self._is_js_candidate(full_url):
                        found_urls.add(full_url)

        return sorted(list(found_urls))

    def _is_js_candidate(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        if path.endswith(".js") or ".js?" in url.lower():
            return True
        if "static/chunks" in path or "webpack" in path:
            return True
        return False
