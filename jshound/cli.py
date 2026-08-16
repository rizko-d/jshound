#!/usr/bin/env python3
"""
JSHound - Fast Frontend JS Static Analyzer & Secret/Endpoint Hunter
"""

import sys
import os
import argparse
from typing import Dict, List, Set, Any

from jshound.crawler import JSCrawler
from jshound.analyzer import JSAnalyzer
from jshound.sourcemap import SourceMapUnpacker
from jshound.reporter import Reporter, Colors
from jshound.web import start_web_server
from jshound.diff import ScanDiffer

def main():
    parser = argparse.ArgumentParser(
        description="JSHound - Advanced Frontend JS Static Reconnaissance, DOM Vulnerability & Multi-Cloud Secret Hunter",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-u", "--url", help="Target webpage URL or direct .js file URL")
    group.add_argument("-f", "--file", help="Local JS file or directory to scan offline")
    group.add_argument("-w", "--web", action="store_true", help="Launch interactive Dark-themed Web Dashboard")

    parser.add_argument("-p", "--port", type=int, default=8899, help="Port for web dashboard (default: 8899)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically when running in web mode")
    parser.add_argument("-o", "--output-dir", default="output", help="Directory to save output reports and unpacked source maps (default: ./output)")
    parser.add_argument("--no-sourcemap", action="store_true", help="Disable automatic sourcemap (.map) detection and unpacking")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP request timeout in seconds (default: 15)")
    parser.add_argument("-k", "--insecure", action="store_true", help="Allow insecure SSL connections")
    parser.add_argument("-H", "--header", action="append", help="Custom HTTP header (format: 'Key: Value'). Can be repeated.")
    parser.add_argument("--entropy", type=float, default=4.5, help="Minimum Shannon entropy threshold for secret heuristic (default: 4.5)")
    parser.add_argument("--diff", help="Path to historical scan JSON file to perform continuous change diffing")

    args = parser.parse_args()

    # If no arguments provided or --web explicitly set, start web dashboard
    if args.web or (not args.url and not args.file):
        reporter = Reporter(target_url="Web Interface")
        reporter.print_banner()
        start_web_server(port=args.port, auto_open=not args.no_browser)
        return

    # Parse headers if supplied
    custom_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()

    target_display = args.url if args.url else args.file
    reporter = Reporter(target_url=target_display)
    reporter.print_banner()

    crawler = JSCrawler(timeout=args.timeout, headers=custom_headers if custom_headers else None, verify_ssl=not args.insecure)
    analyzer = JSAnalyzer(min_entropy=args.entropy)
    unpacker = SourceMapUnpacker()

    aggregated: Dict[str, Any] = {
        "target": target_display,
        "files_analyzed": [],
        "sourcemaps_unpacked": [],
        "secrets": [],
        "endpoints": set(),
        "internal_hosts": set(),
        "dom_vulns": [],
        "graphql_queries": [],
        "api_blueprints": []
    }

    # 1. ONLINE MODE
    if args.url:
        target_url = args.url
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "https://" + target_url

        print(f"{Colors.BLUE}[*] Fetching and crawling initial target: {target_url}{Colors.ENDC}")
        initial_content, err = crawler.fetch_url(target_url)

        if not initial_content:
            print(f"{Colors.FAIL}[-] Failed to fetch {target_url}. Reason: {err}{Colors.ENDC}")
            sys.exit(1)

        # Check if URL itself is a JS file
        if target_url.split("?")[0].endswith(".js"):
            js_urls = [target_url]
        else:
            print(f"{Colors.CYAN}[*] Extracting JavaScript scripts & bundles from HTML...{Colors.ENDC}")
            js_urls = crawler.extract_js_links(target_url, initial_content)
            # Also scan inline scripts from the HTML
            html_scan = analyzer.scan(initial_content, source_url=target_url + " (inline)")
            for s in html_scan["secrets"]:
                s["source"] = target_url + " (inline)"
                aggregated["secrets"].append(s)
            aggregated["endpoints"].update(html_scan["endpoints"])
            aggregated["internal_hosts"].update(html_scan["internal_hosts"])
            aggregated["dom_vulns"].extend(html_scan["dom_vulns"])
            aggregated["graphql_queries"].extend(html_scan["graphql_queries"])
            aggregated["api_blueprints"].extend(html_scan["api_blueprints"])

        print(f"{Colors.GREEN}[+] Found {len(js_urls)} JavaScript files/chunks.{Colors.ENDC}")

        for idx, js_url in enumerate(js_urls, start=1):
            print(f"  [{idx}/{len(js_urls)}] Scanning: {js_url}")
            js_content, _ = crawler.fetch_url(js_url)
            if not js_content:
                continue

            aggregated["files_analyzed"].append(js_url)
            
            # Static scan
            scan_res = analyzer.scan(js_content, source_url=js_url)
            for s in scan_res["secrets"]:
                s["source"] = js_url
                aggregated["secrets"].append(s)
            aggregated["endpoints"].update(scan_res["endpoints"])
            aggregated["internal_hosts"].update(scan_res["internal_hosts"])
            aggregated["dom_vulns"].extend(scan_res["dom_vulns"])
            aggregated["graphql_queries"].extend(scan_res["graphql_queries"])
            aggregated["api_blueprints"].extend(scan_res["api_blueprints"])

            # Sourcemap detection & unpacking
            if not args.no_sourcemap:
                map_url = unpacker.detect_map_url(js_url, js_content)
                if map_url:
                    map_content, _ = crawler.fetch_url(map_url)
                    if map_content:
                        target_dir = os.path.join(args.output_dir, "unpacked_sourcemaps", os.path.basename(js_url).replace(".js", ""))
                        count, files = unpacker.unpack(map_content, target_dir)
                        if count > 0:
                            print(f"      {Colors.GREEN}↳ [SourceMap] Unpacked {count} original source files to {target_dir}{Colors.ENDC}")
                            aggregated["sourcemaps_unpacked"].append({
                                "map_url": map_url,
                                "unpacked_count": count,
                                "dest_dir": target_dir
                            })
                            # Scan all unpacked source files
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
                                        aggregated["dom_vulns"].extend(src_scan["dom_vulns"])
                                        aggregated["graphql_queries"].extend(src_scan["graphql_queries"])
                                        aggregated["api_blueprints"].extend(src_scan["api_blueprints"])
                                except Exception:
                                    pass

    # 2. LOCAL FILE / DIR SCAN MODE
    elif args.file:
        local_path = os.path.abspath(args.file)
        files_to_scan = []
        if os.path.isdir(local_path):
            for root, _, filenames in os.walk(local_path):
                for fn in filenames:
                    if fn.endswith(".js") or fn.endswith(".ts") or fn.endswith(".tsx") or fn.endswith(".jsx") or fn.endswith(".json"):
                        files_to_scan.append(os.path.join(root, fn))
        elif os.path.isfile(local_path):
            files_to_scan.append(local_path)

        print(f"{Colors.GREEN}[+] Found {len(files_to_scan)} local files to analyze.{Colors.ENDC}")

        for idx, fpath in enumerate(files_to_scan, start=1):
            rel_name = os.path.relpath(fpath, local_path) if os.path.isdir(local_path) else os.path.basename(fpath)
            print(f"  [{idx}/{len(files_to_scan)}] Scanning: {rel_name}")
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    aggregated["files_analyzed"].append(rel_name)
                    scan_res = analyzer.scan(content, source_url=rel_name)
                    for s in scan_res["secrets"]:
                        s["source"] = rel_name
                        aggregated["secrets"].append(s)
                    aggregated["endpoints"].update(scan_res["endpoints"])
                    aggregated["internal_hosts"].update(scan_res["internal_hosts"])
                    aggregated["dom_vulns"].extend(scan_res["dom_vulns"])
                    aggregated["graphql_queries"].extend(scan_res["graphql_queries"])
                    aggregated["api_blueprints"].extend(scan_res["api_blueprints"])
            except Exception as e:
                print(f"    {Colors.FAIL}[-] Error reading {fpath}: {e}{Colors.ENDC}")

    # Convert sets to sorted lists for clean serialization
    aggregated["endpoints"] = sorted(list(aggregated["endpoints"]))
    aggregated["internal_hosts"] = sorted(list(aggregated["internal_hosts"]))

    # Output reports
    reporter.print_summary_terminal(aggregated)
    reporter.export_all(aggregated, args.output_dir)

    # Feature 6: Diff Mode Execution
    if args.diff:
        try:
            old_data = ScanDiffer.load_scan(args.diff)
            diff_res = ScanDiffer.compare(old_data, aggregated)
            reporter.print_diff_terminal(diff_res)
        except Exception as e:
            print(f"\n{Colors.FAIL}[-] Diff Comparison Error: {e}{Colors.ENDC}")

if __name__ == "__main__":
    main()
