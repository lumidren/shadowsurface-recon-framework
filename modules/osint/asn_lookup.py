"""
Autonomous System Number (ASN) & BGP Route Lookup
Maps IP addresses to their origin Autonomous System, ISP, and network routing block.
"""

import requests
from typing import Dict, Any

BGP_API_URL = "https://ipapi.co/{ip}/json/"

def lookup_asn(ip: str, timeout: int = 8) -> Dict[str, Any]:
    """
    Queries BGP/ASN routing details for a given IP address.
    """
    clean_ip = ip.strip()
    result = {
        "ip": clean_ip,
        "asn": "Unknown",
        "org": "Unknown",
        "network": "Unknown",
        "country": "Unknown"
    }

    if not clean_ip or clean_ip.startswith("127.") or clean_ip.startswith("10.") or clean_ip.startswith("192.168."):
        return result

    try:
        url = BGP_API_URL.format(ip=clean_ip)
        resp = requests.get(url, headers={"User-Agent": "ShadowSurface/2.0"}, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            result["asn"] = data.get("asn", "Unknown")
            result["org"] = data.get("org", "Unknown")
            result["network"] = data.get("network", "Unknown")
            result["country"] = data.get("country_name", "Unknown")
    except Exception:
        pass

    return result
