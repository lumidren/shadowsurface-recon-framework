"""
Mixed Content & Insecure Subresource Crawler
Crawls HTTPS homepages for insecure cleartext 'http://' scripts, styles, and iframe inclusions.
"""

from typing import Dict, Any, List
import re
import requests

def scan_mixed_content(domain: str) -> Dict[str, Any]:
    """Scans domain for insecure subresources loaded over HTTP."""
    res = {
        "domain": domain,
        "has_mixed_content": False,
        "insecure_resources": []
    }
    try:
        r = requests.get(f"https://{domain}", timeout=5, headers={"User-Agent": "ShadowSurface/2.0"}, verify=False)
        pattern = re.compile(r'(src|href)=["\'](http://[^"\']+)["\']', re.IGNORECASE)
        matches = pattern.findall(r.text)

        for attr, url in matches:
            if not url.startswith("http://localhost") and not url.startswith("http://127.0.0.1"):
                res["has_mixed_content"] = True
                res["insecure_resources"].append({"attribute": attr, "url": url})
    except Exception:
        pass

    return res
