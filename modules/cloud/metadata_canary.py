"""
Cloud Instance Metadata (IMDS) Canary Probe
Tests reverse proxies / web endpoints for SSRF reflections exposing 169.254.169.254.
"""

from typing import Dict, Any
import requests

def probe_imds_reflection(domain: str) -> Dict[str, Any]:
    """Tests if target endpoint reflects cloud metadata canary."""
    res = {
        "domain": domain,
        "metadata_exposed": False,
        "severity": "Low"
    }
    canary_url = f"https://{domain}/?proxy=http://169.254.169.254/latest/meta-data/"
    try:
        r = requests.get(canary_url, timeout=3, verify=False)
        if "ami-id" in r.text or "instance-id" in r.text:
            res["metadata_exposed"] = True
            res["severity"] = "CRITICAL"
            res["details"] = "SSRF vulnerability exposes AWS/Cloud IMDS metadata credentials."
    except Exception:
        pass

    return res
