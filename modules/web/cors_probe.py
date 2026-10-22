"""
Cross-Origin Resource Sharing (CORS) Misconfiguration Probe
Tests for arbitrary origin reflection and unauthenticated cross-origin credential leaks.
"""

from typing import Dict, Any
import requests

def probe_cors_policy(domain: str) -> Dict[str, Any]:
    """Tests for permissive CORS policies."""
    res = {
        "domain": domain,
        "arbitrary_origin_allowed": False,
        "credentials_supported": False,
        "vulnerable": False,
        "severity": "Low"
    }
    evil_origin = "https://attacker-origin.shadowrecon.com"
    try:
        headers = {
            "User-Agent": "ShadowSurface/2.0",
            "Origin": evil_origin
        }
        r = requests.get(f"https://{domain}", timeout=5, headers=headers, verify=False)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if evil_origin in acao:
            res["arbitrary_origin_allowed"] = True
            if acac == "true":
                res["credentials_supported"] = True
                res["vulnerable"] = True
                res["severity"] = "CRITICAL"
            else:
                res["vulnerable"] = True
                res["severity"] = "MEDIUM"
        elif acao == "*" and acac == "true":
            res["vulnerable"] = True
            res["severity"] = "HIGH"
    except Exception:
        pass

    return res
