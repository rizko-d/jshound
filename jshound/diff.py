import json
import os
from typing import Dict, List, Set, Any

class ScanDiffer:
    @staticmethod
    def load_scan(filepath: str) -> Dict[str, Any]:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Historical scan file not found: {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def compare(old_scan: Dict[str, Any], new_scan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compares two scan result sets and outputs added, removed, and persistent findings.
        """
        old_secrets = {s["value"]: s for s in old_scan.get("secrets", [])}
        new_secrets = {s["value"]: s for s in new_scan.get("secrets", [])}

        old_endpoints = set(old_scan.get("endpoints", []))
        new_endpoints = set(new_scan.get("endpoints", []))

        old_hosts = set(old_scan.get("internal_hosts", []))
        new_hosts = set(new_scan.get("internal_hosts", []))

        old_vulns = {v["code"]: v for v in old_scan.get("dom_vulns", [])}
        new_vulns = {v["code"]: v for v in new_scan.get("dom_vulns", [])}

        diff_result = {
            "target": new_scan.get("target", "Target"),
            "new_secrets": [new_secrets[v] for v in new_secrets if v not in old_secrets],
            "resolved_secrets": [old_secrets[v] for v in old_secrets if v not in new_secrets],
            "new_endpoints": sorted(list(new_endpoints - old_endpoints)),
            "removed_endpoints": sorted(list(old_endpoints - new_endpoints)),
            "new_hosts": sorted(list(new_hosts - old_hosts)),
            "new_dom_vulns": [new_vulns[c] for c in new_vulns if c not in old_vulns]
        }

        return diff_result
