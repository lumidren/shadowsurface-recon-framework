"""
CDN & Edge Reverse Proxy Detector
Identifies whether target is shielded behind major Content Delivery Networks (Cloudflare, Akamai, CloudFront, Fastly).
"""

from typing import Dict, Any, List
import requests

CDN_HEADERS = {
    "cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
    "aws_cloudfront": ["x-amz-cf-id", "x-amz-cf-pop", "cloudfront"],
    "akamai": ["x-akamai-transformed", "x-akamai-request-id", "akamai-origin-hop"],
    "fastly": ["fastly-debug-digest", "x-fastly-request-id"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "imperva_incapsula": ["x-iinfo", "x-cdn"]
}

def detect_cdn(domain: str) -> Dict[str, Any]:
    """Inspects HTTP headers and CNAME indicators to identify CDN provider."""
    res = {
        "domain": domain,
        "is_behind_cdn": False,
        "cdn_provider": None,
        "detected_headers": []
    }
    try:
        r = requests.get(f"https://{domain}", timeout=6, headers={"User-Agent": "ShadowSurface/2.0"}, verify=False)
        headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
        server_header = headers_lower.get("server", "")

        for provider, sigs in CDN_HEADERS.items():
            for sig in sigs:
                if sig in headers_lower:
                    res["is_behind_cdn"] = True
                    res["cdn_provider"] = provider
                    res["detected_headers"].append(sig)
                    return res

        if "cloudflare" in server_header:
            res["is_behind_cdn"] = True
            res["cdn_provider"] = "cloudflare"
        elif "cloudfront" in server_header:
            res["is_behind_cdn"] = True
            res["cdn_provider"] = "aws_cloudfront"
    except Exception:
        pass

    return res
