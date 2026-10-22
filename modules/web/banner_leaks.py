"""
Server Banner & Technology Header Disclosure Auditor
Scans for detailed software version leakages in Server, X-Powered-By, and X-AspNet-Version.
"""

from typing import Dict, Any, List
import re

LEAK_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "via", "x-backend-server"
]

def audit_banner_leaks(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Identifies information leaks in HTTP response headers."""
    leaks = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for h in LEAK_HEADERS:
        if h in headers_lower:
            val = headers_lower[h]
            has_version = bool(re.search(r'\d+\.\d+', val))
            leaks.append({
                "header": h,
                "value": val,
                "discloses_version": has_version,
                "severity": "Medium" if has_version else "Low"
            })

    return leaks
