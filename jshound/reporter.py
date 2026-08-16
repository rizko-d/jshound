import json
import os
from typing import Dict, List, Any

# ANSI Color codes for zero-dep terminal styling
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

class Reporter:
    def __init__(self, target_url: str):
        self.target_url = target_url

    def print_banner(self):
        banner = f"""{Colors.CYAN}{Colors.BOLD}
      __ _____ _   _                       _ 
   _  \\ / ____| | | |                     | |
  (_) | | (___ | |_| | ___  _   _ _ __   __| |
    | | |\\___ \\|  _  |/ _ \\| | | | '_ \\ / _` |
    | | |____) | | | | (_) | |_| | | | | (_| |
    |_|_|_____/|_| |_|\\___/ \\__,_|_| |_|\\__,_|
{Colors.DIM}   Fast JS Recon & Secret/Endpoint Hunter (v0.1.0){Colors.ENDC}
        """
        print(banner)

    def print_summary_terminal(self, aggregated: Dict[str, Any]):
        print(f"\n{Colors.BOLD}[*] Target:{Colors.ENDC} {self.target_url}")
        print(f"{Colors.BOLD}[*] Total JS Files Analyzed:{Colors.ENDC} {len(aggregated.get('files_analyzed', []))}")
        print(f"{Colors.BOLD}[*] Source Maps Unpacked:{Colors.ENDC} {len(aggregated.get('sourcemaps_unpacked', []))}")
        
        # 1. Secrets Found
        secrets = aggregated.get("secrets", [])
        print(f"\n{Colors.BOLD}{Colors.FAIL if secrets else Colors.GREEN}[+] Potential Secrets / Credentials Found: {len(secrets)}{Colors.ENDC}")
        for sec in secrets:
            print(f"  {Colors.WARNING}[!] {sec['type']}{Colors.ENDC}")
            print(f"      Value  : {Colors.BOLD}{sec['value']}{Colors.ENDC}")
            print(f"      Source : {Colors.DIM}{sec['source']}{Colors.ENDC}")
            print(f"      Context: {Colors.DIM}{sec['context']}{Colors.ENDC}\n")

        # 2. Internal & Staging Hosts
        hosts = aggregated.get("internal_hosts", [])
        print(f"{Colors.BOLD}{Colors.CYAN}[+] Internal / Staging / Private Hosts Found: {len(hosts)}{Colors.ENDC}")
        for host in hosts:
            print(f"  -> {Colors.BOLD}{host}{Colors.ENDC}")

        # 3. Discovered Endpoints Preview
        endpoints = aggregated.get("endpoints", [])
        print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Unique Endpoints / Paths Discovered: {len(endpoints)}{Colors.ENDC}")
        preview_count = min(15, len(endpoints))
        for ep in endpoints[:preview_count]:
            print(f"  • {ep}")
        if len(endpoints) > preview_count:
            print(f"  {Colors.DIM}... and {len(endpoints) - preview_count} more (exported to output){Colors.ENDC}")

    def export_json(self, aggregated: Dict[str, Any], filepath: str):
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(aggregated, f, indent=2)
        print(f"\n{Colors.GREEN}[✓] Full JSON results saved to: {filepath}{Colors.ENDC}")

    def export_endpoints_txt(self, endpoints: List[str], filepath: str):
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            for ep in endpoints:
                f.write(f"{ep}\n")
        print(f"{Colors.GREEN}[✓] Endpoints wordlist saved to: {filepath}{Colors.ENDC}")

    def export_markdown_report(self, aggregated: Dict[str, Any], filepath: str):
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        md = f"""# 🛡️ JSHound Security Reconnaissance Report

**Target URL:** `{self.target_url}`  
**Analyzed Files:** `{len(aggregated.get('files_analyzed', []))}`  
**Source Maps Extracted:** `{len(aggregated.get('sourcemaps_unpacked', []))}`  

---

## 1. 🔑 Exposed Secrets & API Tokens ({len(aggregated.get('secrets', []))})

| Type | Value | Source File |
| :--- | :--- | :--- |
"""
        for s in aggregated.get("secrets", []):
            md += f"| **{s['type']}** | `{s['value']}` | `{s['source']}` |\n"

        md += f"""
---

## 2. 🏢 Internal & Staging Hosts ({len(aggregated.get('internal_hosts', []))})

"""
        for h in aggregated.get("internal_hosts", []):
            md += f"- `{h}`\n"

        md += f"""
---

## 3. 🌐 Discovered Endpoints & Paths ({len(aggregated.get('endpoints', []))})

```text
"""
        for ep in aggregated.get("endpoints", []):
            md += f"{ep}\n"

        md += "```\n"

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"{Colors.GREEN}[✓] Markdown report saved to: {filepath}{Colors.ENDC}")
