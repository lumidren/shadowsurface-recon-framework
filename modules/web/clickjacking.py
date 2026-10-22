"""
Clickjacking & Frame-Busting Posture Auditor
Audits X-Frame-Options and CSP frame-ancestors to prevent UI redressing attacks.
"""

from typing import Dict, Any

def audit_clickjacking_protection(headers: Dict[str, str]) -> Dict[str, Any]:
    """Analyzes framing protection headers."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    xfo = headers_lower.get("x-frame-options", "").upper()
    csp = headers_lower.get("content-security-policy", "").lower()

    res = {
        "protected": False,
        "x_frame_options": xfo or None,
        "csp_frame_ancestors": None,
        "risk_level": "Medium"
    }

    if "frame-ancestors" in csp:
        res["protected"] = True
        res["risk_level"] = "Low"
        for directive in csp.split(";"):
            if "frame-ancestors" in directive:
                res["csp_frame_ancestors"] = directive.strip()
                break
    elif xfo in ["DENY", "SAMEORIGIN"]:
        res["protected"] = True
        res["risk_level"] = "Low"
    else:
        res["protected"] = False
        res["risk_level"] = "Medium"

    return res
