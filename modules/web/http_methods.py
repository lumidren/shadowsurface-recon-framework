"""
HTTP Dangerous Methods & Cross-Site Tracing (XST) Probe
Probes OPTIONS, TRACE, PUT, and DELETE methods to detect dangerous verb enablement.
"""

from typing import Dict, Any, List
import requests

def audit_http_methods(domain: str) -> Dict[str, Any]:
    """Tests allowed HTTP verbs."""
    res = {
        "domain": domain,
        "allowed_methods": [],
        "trace_enabled": False,
        "put_delete_enabled": False,
        "issues": []
    }
    try:
        r = requests.options(f"https://{domain}", timeout=5, headers={"User-Agent": "ShadowSurface/2.0"}, verify=False)
        allow_header = r.headers.get("Allow", "") or r.headers.get("Public", "")
        if allow_header:
            methods = [m.strip().upper() for m in allow_header.split(",")]
            res["allowed_methods"] = methods
            if "TRACE" in methods:
                res["trace_enabled"] = True
                res["issues"].append("HIGH: HTTP TRACE method enabled (Vulnerable to Cross-Site Tracing XST).")
            if "PUT" in methods or "DELETE" in methods:
                res["put_delete_enabled"] = True
                res["issues"].append("MEDIUM: HTTP PUT/DELETE methods advertised in Allow header.")
    except Exception:
        pass

    return res
