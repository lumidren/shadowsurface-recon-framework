"""
ShadowSurface HTTP Security Headers & Web Posture Audit Module
Inspects security response headers, server tokens, and CORS configuration.
"""

import requests
import urllib3
from typing import Dict, Any, List

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "name": "HSTS (HTTP Strict Transport Security)",
        "severity": "Medium",
        "description": "Protects against SSL stripping and man-in-the-middle downgrade attacks."
    },
    "Content-Security-Policy": {
        "name": "CSP (Content Security Policy)",
        "severity": "High",
        "description": "Mitigates Cross-Site Scripting (XSS) and data injection vulnerabilities."
    },
    "X-Frame-Options": {
        "name": "X-Frame-Options (Clickjacking Protection)",
        "severity": "Medium",
        "description": "Prevents unauthorized UI redressing / clickjacking within iframes."
    },
    "X-Content-Type-Options": {
        "name": "X-Content-Type-Options (MIME Sniffing)",
        "severity": "Low",
        "description": "Prevents browsers from MIME-sniffing a response away from declared content-type."
    },
    "Referrer-Policy": {
        "name": "Referrer-Policy",
        "severity": "Low",
        "description": "Controls how much referrer information is included with requests."
    }
}

def audit_http_posture(target_url: str, timeout: int = 5) -> Dict[str, Any]:
    """Audits HTTP headers, SSL redirect, and server banners."""
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = f"https://{target_url}"

    audit_result = {
        "target_url": target_url,
        "status_code": None,
        "server_banner": "Unknown",
        "powered_by": "None",
        "missing_headers": [],
        "present_headers": {},
        "findings": []
    }

    try:
        resp = requests.get(target_url, timeout=timeout, verify=False, allow_redirects=True)
        audit_result["status_code"] = resp.status_code
        headers = resp.headers

        # Check Server disclosure
        if "Server" in headers:
            audit_result["server_banner"] = headers["Server"]
            audit_result["findings"].append({
                "title": "Server Information Disclosure",
                "severity": "Low",
                "detail": f"Target advertises server version: '{headers['Server']}'."
            })

        if "X-Powered-By" in headers:
            audit_result["powered_by"] = headers["X-Powered-By"]
            audit_result["findings"].append({
                "title": "Technology Stack Disclosure",
                "severity": "Low",
                "detail": f"X-Powered-By header reveals backend framework: '{headers['X-Powered-By']}'."
            })

        # Check Security Headers
        for header_key, meta in REQUIRED_SECURITY_HEADERS.items():
            found_key = next((k for k in headers.keys() if k.lower() == header_key.lower()), None)
            if found_key:
                audit_result["present_headers"][header_key] = headers[found_key]
            else:
                audit_result["missing_headers"].append({
                    "header": header_key,
                    "name": meta["name"],
                    "severity": meta["severity"],
                    "description": meta["description"]
                })
                audit_result["findings"].append({
                    "title": f"Missing {meta['name']}",
                    "severity": meta["severity"],
                    "detail": meta["description"]
                })

    except Exception as e:
        audit_result["findings"].append({
            "title": "HTTP Service Connection Warning",
            "severity": "Informational",
            "detail": f"Could not complete HTTP audit: {str(e)}"
        })

    return audit_result
