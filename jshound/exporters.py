import json
import urllib.parse
from typing import Dict, List, Any

class Exporters:
    @staticmethod
    def to_postman_collection(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Converts discovered endpoints and blueprints into a valid Postman Collection v2.1.0 schema.
        """
        target = data.get("target", "Target API")
        parsed_target = urllib.parse.urlparse(target if target.startswith("http") else f"https://{target}")
        base_host = parsed_target.netloc or "target.com"
        protocol = parsed_target.scheme or "https"

        collection = {
            "info": {
                "_postman_id": "jshound-recon-collection",
                "name": f"JSHound Recon - {base_host}",
                "description": f"Auto-generated reconnaissance endpoints and API blueprints from {target} by JSHound.",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": []
        }

        # Organize by folder
        endpoints = data.get("endpoints", [])
        blueprints = {b["endpoint"]: b for b in data.get("api_blueprints", [])}

        folders: Dict[str, List[Dict[str, Any]]] = {}

        for ep in endpoints:
            # Determine path & folder
            ep_clean = ep.split("?")[0]
            parts = [p for p in ep_clean.strip("/").split("/") if p]
            folder_name = parts[0].upper() if parts else "ROOT"
            
            if folder_name not in folders:
                folders[folder_name] = []

            # Check if we have blueprint data
            bp = blueprints.get(ep, {})
            method = bp.get("method", "GET")
            
            # Construct URL object
            if ep.startswith("http://") or ep.startswith("https://"):
                parsed_ep = urllib.parse.urlparse(ep)
                host_parts = parsed_ep.netloc.split(".")
                path_parts = [p for p in parsed_ep.path.strip("/").split("/") if p]
                query_params = []
                if parsed_ep.query:
                    for q in parsed_ep.query.split("&"):
                        if "=" in q:
                            k, v = q.split("=", 1)
                            query_params.append({"key": k, "value": v})
                        elif q:
                            query_params.append({"key": q, "value": ""})
                raw_url = ep
            else:
                host_parts = base_host.split(".")
                path_parts = parts
                query_params = []
                if "?" in ep:
                    q_str = ep.split("?", 1)[1]
                    for q in q_str.split("&"):
                        if "=" in q:
                            k, v = q.split("=", 1)
                            query_params.append({"key": k, "value": v})
                        elif q:
                            query_params.append({"key": q, "value": ""})
                raw_url = f"{protocol}://{base_host}{ep if ep.startswith('/') else '/' + ep}"

            item = {
                "name": ep,
                "request": {
                    "method": method,
                    "header": [
                        {"key": "User-Agent", "value": "JSHound-Pentest-Agent", "type": "text"}
                    ],
                    "url": {
                        "raw": raw_url,
                        "protocol": protocol,
                        "host": host_parts,
                        "path": path_parts,
                        "query": query_params
                    },
                    "description": f"Discovered by JSHound Recon."
                },
                "response": []
            }
            folders[folder_name].append(item)

        for f_name, items in folders.items():
            collection["item"].append({
                "name": f_name,
                "item": items
            })

        return collection

    @staticmethod
    def to_openapi_spec(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Converts discovered endpoints into OpenAPI 3.0.0 Specification.
        """
        target = data.get("target", "Target API")
        parsed_target = urllib.parse.urlparse(target if target.startswith("http") else f"https://{target}")
        base_host = parsed_target.netloc or "target.com"
        protocol = parsed_target.scheme or "https"

        openapi = {
            "openapi": "3.0.0",
            "info": {
                "title": f"JSHound Recon API - {base_host}",
                "description": f"Auto-generated OpenAPI blueprint from client-side JS bundles of {target}.",
                "version": "1.0.0"
            },
            "servers": [
                {"url": f"{protocol}://{base_host}", "description": "Target Server"}
            ],
            "paths": {}
        }

        blueprints = {b["endpoint"]: b for b in data.get("api_blueprints", [])}

        for ep in data.get("endpoints", []):
            if ep.startswith("http://") or ep.startswith("https://"):
                path_only = urllib.parse.urlparse(ep).path
            else:
                path_only = ep.split("?")[0]

            if not path_only.startswith("/"):
                path_only = "/" + path_only

            if path_only not in openapi["paths"]:
                openapi["paths"][path_only] = {}

            bp = blueprints.get(ep, {})
            method = bp.get("method", "get").lower()

            parameters = []
            if "?" in ep:
                q_str = ep.split("?", 1)[1]
                for q in q_str.split("&"):
                    param_name = q.split("=")[0]
                    if param_name:
                        parameters.append({
                            "name": param_name,
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string"}
                        })

            openapi["paths"][path_only][method] = {
                "summary": f"Discovered endpoint {path_only}",
                "description": f"Original discovered pattern: {ep}",
                "parameters": parameters,
                "responses": {
                    "200": {
                        "description": "Successful discovery response"
                    }
                }
            }

        return openapi
