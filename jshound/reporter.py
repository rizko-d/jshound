import json
import os
from typing import Dict, List, Any
from jshound.exporters import Exporters

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
{Colors.DIM}   Next-Gen JS Static Recon & Vulnerability Hunter (v0.2.0){Colors.ENDC}
        """
        print(banner)

    def print_summary_terminal(self, aggregated: Dict[str, Any]):
        print(f"\n{Colors.BOLD}[*] Target:{Colors.ENDC} {self.target_url}")
        print(f"{Colors.BOLD}[*] Total JS Files Analyzed:{Colors.ENDC} {len(aggregated.get('files_analyzed', []))}")
        print(f"{Colors.BOLD}[*] Source Maps Unpacked:{Colors.ENDC} {len(aggregated.get('sourcemaps_unpacked', []))}")
        
        # 1. Secrets Found
        secrets = aggregated.get("secrets", [])
        print(f"\n{Colors.BOLD}{Colors.FAIL if secrets else Colors.GREEN}[+] Exposed Secrets & High-Entropy Tokens: {len(secrets)}{Colors.ENDC}")
        for sec in secrets:
            entropy_info = f" [Entropy: {sec.get('entropy')}]" if sec.get('entropy') else ""
            print(f"  {Colors.WARNING}[!] {sec['type']}{entropy_info}{Colors.ENDC}")
            print(f"      Value  : {Colors.BOLD}{sec['value']}{Colors.ENDC}")
            print(f"      Source : {Colors.DIM}{sec['source']}{Colors.ENDC}")
            print(f"      Context: {Colors.DIM}{sec['context']}{Colors.ENDC}\n")

        # 2. DOM Vulnerabilities
        dom_vulns = aggregated.get("dom_vulns", [])
        if dom_vulns:
            print(f"{Colors.BOLD}{Colors.FAIL}[!] Potential DOM XSS & Dangerous Sinks Found: {len(dom_vulns)}{Colors.ENDC}")
            for v in dom_vulns[:10]:
                print(f"  {Colors.WARNING}↳ [{v['type']}]{Colors.ENDC} in {Colors.DIM}{v['source']}{Colors.ENDC}")
                print(f"    {Colors.DIM}{v['code']}{Colors.ENDC}")
            if len(dom_vulns) > 10:
                print(f"  {Colors.DIM}... and {len(dom_vulns) - 10} more DOM sinks (saved to reports){Colors.ENDC}\n")

        # 3. GraphQL Queries
        gql = aggregated.get("graphql_queries", [])
        if gql:
            print(f"\n{Colors.BOLD}{Colors.CYAN}[+] Discovered GraphQL Queries/Mutations: {len(gql)}{Colors.ENDC}")
            for g in gql[:5]:
                print(f"  {Colors.DIM}• {g['query'][:80]}... ({g['source']}){Colors.ENDC}")

        # 4. Internal & Staging Hosts
        hosts = aggregated.get("internal_hosts", [])
        if hosts:
            print(f"\n{Colors.BOLD}{Colors.CYAN}[+] Internal / Staging / Private Hosts Found: {len(hosts)}{Colors.ENDC}")
            for host in hosts:
                print(f"  -> {Colors.BOLD}{host}{Colors.ENDC}")

        # 5. Discovered Endpoints Preview
        endpoints = aggregated.get("endpoints", [])
        print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Unique Endpoints / Paths Discovered: {len(endpoints)}{Colors.ENDC}")
        preview_count = min(15, len(endpoints))
        for ep in endpoints[:preview_count]:
            print(f"  • {ep}")
        if len(endpoints) > preview_count:
            print(f"  {Colors.DIM}... and {len(endpoints) - preview_count} more (exported to output){Colors.ENDC}")

    def print_diff_terminal(self, diff: Dict[str, Any]):
        print(f"\n{Colors.BOLD}{Colors.HEADER}=== Continuous Reconnaissance Diff Results ==={Colors.ENDC}")
        print(f"Target: {diff['target']}\n")

        new_secrets = diff.get("new_secrets", [])
        if new_secrets:
            print(f"{Colors.FAIL}{Colors.BOLD}🚨 [NEW LEAKS DETECTED] ({len(new_secrets)}){Colors.ENDC}")
            for s in new_secrets:
                print(f"  + {s['type']}: {s['value']} ({s['source']})")
        else:
            print(f"{Colors.GREEN}✓ No new secrets leaked.{Colors.ENDC}")

        new_eps = diff.get("new_endpoints", [])
        if new_eps:
            print(f"\n{Colors.GREEN}{Colors.BOLD}🆕 [NEW ENDPOINTS DEPLOYED] ({len(new_eps)}){Colors.ENDC}")
            for ep in new_eps:
                print(f"  + {ep}")

        new_vulns = diff.get("new_dom_vulns", [])
        if new_vulns:
            print(f"\n{Colors.WARNING}{Colors.BOLD}⚠️ [NEW DOM VULNERABILITIES DETECTED] ({len(new_vulns)}){Colors.ENDC}")
            for v in new_vulns:
                print(f"  + {v['type']} in {v['source']}")

    def export_all(self, aggregated: Dict[str, Any], output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        
        # 1. JSON
        json_path = os.path.join(output_dir, "jshound_results.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(aggregated, f, indent=2)
        print(f"\n{Colors.GREEN}[✓] Full JSON results saved to: {json_path}{Colors.ENDC}")

        # 2. Endpoints TXT
        endpoints_path = os.path.join(output_dir, "endpoints.txt")
        with open(endpoints_path, "w", encoding="utf-8") as f:
            for ep in aggregated.get("endpoints", []):
                f.write(f"{ep}\n")
        print(f"{Colors.GREEN}[✓] Endpoints wordlist saved to: {endpoints_path}{Colors.ENDC}")

        # 3. Postman Collection v2.1
        postman_data = Exporters.to_postman_collection(aggregated)
        postman_path = os.path.join(output_dir, "postman_collection.json")
        with open(postman_path, "w", encoding="utf-8") as f:
            json.dump(postman_data, f, indent=2)
        print(f"{Colors.GREEN}[✓] Postman Collection v2.1 saved to: {postman_path}{Colors.ENDC}")

        # 4. OpenAPI Spec 3.0
        openapi_data = Exporters.to_openapi_spec(aggregated)
        openapi_path = os.path.join(output_dir, "openapi_spec.json")
        with open(openapi_path, "w", encoding="utf-8") as f:
            json.dump(openapi_data, f, indent=2)
        print(f"{Colors.GREEN}[✓] OpenAPI 3.0 Blueprint saved to: {openapi_path}{Colors.ENDC}")

        # 5. Markdown Report
        markdown_path = os.path.join(output_dir, "recon_report.md")
        self._export_markdown(aggregated, markdown_path)
        print(f"{Colors.GREEN}[✓] Markdown report saved to: {markdown_path}{Colors.ENDC}")

    def _export_markdown(self, aggregated: Dict[str, Any], filepath: str):
        md = f"""# 🛡️ JSHound Security Reconnaissance Report

**Target URL:** `{self.target_url}`  
**Analyzed Files:** `{len(aggregated.get('files_analyzed', []))}`  
**Source Maps Extracted:** `{len(aggregated.get('sourcemaps_unpacked', []))}`  

---

## 1. 🔑 Exposed Secrets & API Tokens ({len(aggregated.get('secrets', []))})

| Type | Value | Entropy | Source File |
| :--- | :--- | :--- | :--- |
"""
        for s in aggregated.get("secrets", []):
            ent = s.get('entropy', '-')
            md += f"| **{s['type']}** | `{s['value']}` | `{ent}` | `{s['source']}` |\n"

        dom_vulns = aggregated.get("dom_vulns", [])
        md += f"""
---

## 2. 🔬 Potential DOM XSS & Sinks ({len(dom_vulns)})

| Vulnerability Type | Source File | Snippet |
| :--- | :--- | :--- |
"""
        for v in dom_vulns:
            safe_code = v['code'].replace("|", "\\|").replace("\n", " ")
            md += f"| `{v['type']}` | `{v['source']}` | `{safe_code}` |\n"

        gql = aggregated.get("graphql_queries", [])
        md += f"""
---

## 3. 🧬 GraphQL Queries & Mutations ({len(gql)})

"""
        for g in gql:
            md += f"```graphql\n# Source: {g['source']}\n{g['query']}\n```\n\n"

        md += f"""
---

## 4. 🏢 Internal & Staging Hosts ({len(aggregated.get('internal_hosts', []))})

"""
        for h in aggregated.get("internal_hosts", []):
            md += f"- `{h}`\n"

        md += f"""
---

## 5. 🌐 Discovered Endpoints & Paths ({len(aggregated.get('endpoints', []))})

```text
"""
        for ep in aggregated.get("endpoints", []):
            md += f"{ep}\n"

        md += "```\n"

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md)
