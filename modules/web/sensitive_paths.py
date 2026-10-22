"""
Sensitive Endpoint & Path Discovery Crawler
Discovers robots.txt, sitemap.xml, security.txt, and /.well-known/ security endpoints.
"""

from typing import Dict, Any, List
import requests

PROBE_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/humans.txt",
    "/crossdomain.xml"
]

def scan_sensitive_paths(domain: str) -> List[Dict[str, Any]]:
    """Crawls standard public discovery endpoints."""
    discovered = []
    base_url = f"https://{domain}"

    for path in PROBE_PATHS:
        try:
            r = requests.get(f"{base_url}{path}", timeout=4, headers={"User-Agent": "ShadowSurface/2.0"}, verify=False)
            if r.status_code == 200 and len(r.text.strip()) > 0:
                discovered.append({
                    "path": path,
                    "url": f"{base_url}{path}",
                    "status_code": r.status_code,
                    "content_length": len(r.content),
                    "snippet": r.text[:120].strip()
                })
        except Exception:
            continue

    return discovered
