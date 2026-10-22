"""
Subdomain Takeover Engine
Audits CNAME records against known vulnerable cloud and SaaS provider fingerprints.
"""

from typing import Dict, Any, List
import requests

TAKEOVER_SIGNATURES = {
    "github.io": {
        "provider": "GitHub Pages",
        "fingerprint": "There isn't a GitHub Pages site here"
    },
    "s3.amazonaws.com": {
        "provider": "AWS S3",
        "fingerprint": "The specified bucket does not exist"
    },
    "herokuapp.com": {
        "provider": "Heroku",
        "fingerprint": "No such app"
    },
    "azurewebsites.net": {
        "provider": "Azure App Service",
        "fingerprint": "404 Web Site not found"
    },
    "fastly.net": {
        "provider": "Fastly",
        "fingerprint": "Fastly error: unknown domain"
    },
    "surge.sh": {
        "provider": "Surge.sh",
        "fingerprint": "project not found"
    },
    "myshopify.com": {
        "provider": "Shopify",
        "fingerprint": "Sorry, this shop is currently unavailable"
    },
    "wordpress.com": {
        "provider": "WordPress.com",
        "fingerprint": "Do you want to register"
    },
    "zendesk.com": {
        "provider": "Zendesk",
        "fingerprint": "Help Center Closed"
    }
}

def check_subdomain_takeover(hostname: str, cname_target: str) -> Dict[str, Any]:
    """Tests if a CNAME points to an unclaimed cloud resource."""
    result = {
        "hostname": hostname,
        "cname": cname_target,
        "vulnerable": False,
        "provider": None,
        "evidence": None
    }
    target_lower = cname_target.lower()

    for domain_pattern, sig in TAKEOVER_SIGNATURES.items():
        if domain_pattern in target_lower:
            result["provider"] = sig["provider"]
            try:
                r = requests.get(f"http://{hostname}", timeout=5, headers={"User-Agent": "ShadowSurface/2.0"})
                if sig["fingerprint"] in r.text:
                    result["vulnerable"] = True
                    result["evidence"] = f"Detected fingerprint: '{sig['fingerprint']}'"
            except Exception:
                pass
            break

    return result
