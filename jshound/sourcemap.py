import json
import os
import urllib.parse
from typing import Dict, List, Optional, Tuple

class SourceMapUnpacker:
    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir

    def detect_map_url(self, js_url: str, js_content: str) -> Optional[str]:
        # Check sourceMappingURL comment
        # //# sourceMappingURL=app.bundle.js.map
        # /*# sourceMappingURL=app.bundle.js.map */
        lines = js_content.strip().splitlines()
        for line in reversed(lines[-5:]): # usually at the end of file
            if "sourceMappingURL=" in line:
                parts = line.split("sourceMappingURL=")
                if len(parts) > 1:
                    raw_map = parts[1].strip().split()[0].rstrip("*/").strip()
                    if raw_map and not raw_map.startswith("data:"):
                        return urllib.parse.urljoin(js_url, raw_map)
        
        # Default fallback candidate: append .map
        if not js_url.endswith(".map"):
            return js_url + ".map"
        return None

    def unpack(self, map_content: str, target_dir: str) -> Tuple[int, List[str]]:
        """
        Unpacks sourcemap JSON and writes original files if sourcesContent exists.
        Returns: (number of files extracted, list of extracted relative file paths)
        """
        try:
            data = json.loads(map_content)
        except Exception:
            return 0, []

        sources = data.get("sources", [])
        sources_content = data.get("sourcesContent", [])
        
        if not sources or not sources_content or len(sources) != len(sources_content):
            return 0, []

        extracted_files = []
        os.makedirs(target_dir, exist_ok=True)

        for src_path, content in zip(sources, sources_content):
            if not content:
                continue
            
            # Clean path from webpack:// or relative prefix
            clean_path = src_path.replace("webpack://", "").replace("webpack:///", "")
            clean_path = clean_path.replace("../", "").lstrip("/\\")
            clean_path = clean_path.split("?")[0] # remove query params if any

            if not clean_path:
                continue

            full_dest = os.path.join(target_dir, clean_path)
            os.makedirs(os.path.dirname(full_dest), exist_ok=True)

            try:
                with open(full_dest, "w", encoding="utf-8", errors="ignore") as f:
                    f.write(content)
                extracted_files.append(clean_path)
            except Exception:
                pass

        return len(extracted_files), extracted_files
