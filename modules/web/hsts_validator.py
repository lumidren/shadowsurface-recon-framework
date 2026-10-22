"""
HTTP Strict Transport Security (HSTS) Preload & Expiry Validator
Checks RFC 6797 compliance, max-age threshold (>= 1 year), includeSubDomains, and preload eligibility.
"""

from typing import Dict, Any
import re

def validate_hsts(hsts_header: str) -> Dict[str, Any]:
    """Audits Strict-Transport-Security header value."""
    res = {
        "raw_hsts": hsts_header,
        "is_enabled": bool(hsts_header),
        "max_age_seconds": 0,
        "include_subdomains": False,
        "preload": False,
        "grade": "F",
        "issues": []
    }
    if not hsts_header:
        res["issues"].append("CRITICAL: Missing HSTS header. Connections vulnerable to SSL stripping.")
        return res

    match = re.search(r'max-age=(\d+)', hsts_header, re.IGNORECASE)
    if match:
        res["max_age_seconds"] = int(match.group(1))

    if "includesubdomains" in hsts_header.lower():
        res["include_subdomains"] = True
    else:
        res["issues"].append("MEDIUM: HSTS header does not include subdomains (includeSubDomains missing).")

    if "preload" in hsts_header.lower():
        res["preload"] = True

    one_year = 31536000
    if res["max_age_seconds"] >= one_year and res["include_subdomains"] and res["preload"]:
        res["grade"] = "A+"
    elif res["max_age_seconds"] >= one_year and res["include_subdomains"]:
        res["grade"] = "A"
    elif res["max_age_seconds"] >= one_year:
        res["grade"] = "B"
    else:
        res["grade"] = "C"
        res["issues"].append(f"LOW: HSTS max-age is below recommended 1-year threshold ({res['max_age_seconds']}s).")

    return res
