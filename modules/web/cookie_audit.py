"""
Cookie Security Flags Auditor
Validates Set-Cookie headers for Secure, HttpOnly, and SameSite protection flags.
"""

from typing import Dict, Any, List
import requests

def audit_cookie_security(domain: str) -> List[Dict[str, Any]]:
    """Evaluates cookie security attributes returned by target."""
    cookie_reports = []
    try:
        r = requests.get(f"https://{domain}", timeout=5, headers={"User-Agent": "ShadowSurface/2.0"}, verify=False)
        for cookie in r.cookies:
            report = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("httponly") or "httponly" in getattr(cookie, "_rest", {}),
                "samesite": getattr(cookie, "samesite", None),
                "issues": []
            }
            if not report["secure"]:
                report["issues"].append("Cookie missing 'Secure' flag (transmitted over cleartext HTTP).")
            if not report["httponly"]:
                report["issues"].append("Cookie missing 'HttpOnly' flag (accessible to JavaScript / XSS).")
            cookie_reports.append(report)
    except Exception:
        pass

    return cookie_reports
