"""
Web Application Firewall (WAF) Fingerprinting Engine
Detects active commercial and open-source WAF filters via heuristic probe anomalies.
"""

from typing import Dict, Any
import requests

WAF_SIGNATURES = {
    "Cloudflare WAF": ["attention required! | cloudflare", "cf-chl-bypass"],
    "AWS WAF": ["x-amzn-errortype", "awswaf"],
    "Akamai Kona Site Defender": ["akamaighost", "access denied - akamai"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "F5 BIG-IP ASM": ["the requested url was rejected", "ts-cookie"],
    "Imperva Incapsula": ["incapsula_incident_id", "visid_incap"]
}

def fingerprint_waf(domain: str) -> Dict[str, Any]:
    """Sends a harmless canary query to trigger WAF identification signatures."""
    res = {
        "domain": domain,
        "waf_detected": False,
        "waf_name": "None / Undetected",
        "evidence": None
    }
    test_url = f"https://{domain}/?test=<script>alert(1)</script>"
    try:
        r = requests.get(test_url, timeout=6, headers={"User-Agent": "ShadowSurface/2.0"}, verify=False)
        body = r.text.lower()
        headers_str = " ".join([f"{k}: {v}" for k, v in r.headers.items()]).lower()

        for waf, patterns in WAF_SIGNATURES.items():
            for p in patterns:
                if p in body or p in headers_str:
                    res["waf_detected"] = True
                    res["waf_name"] = waf
                    res["evidence"] = f"Triggered match: '{p}' (HTTP {r.status_code})"
                    return res
    except Exception:
        pass

    return res
