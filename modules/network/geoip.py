"""
GeoIP and ISP Geolocation Resolver
Resolves public IP addresses to geographical location, ISP, organization, and country code.
"""

import requests
from typing import Dict, Any

def resolve_geoip(ip: str, timeout: int = 8) -> Dict[str, Any]:
    """Retrieves country, city, coordinates and ASN/ISP for an IP."""
    geo = {
        "ip": ip,
        "country": "Unknown",
        "country_code": "XX",
        "region": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "latitude": 0.0,
        "longitude": 0.0
    }
    if not ip or ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
        return geo

    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", headers={"User-Agent": "ShadowSurface/2.0"}, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            geo["country"] = data.get("country_name", "Unknown")
            geo["country_code"] = data.get("country_code", "XX")
            geo["region"] = data.get("region", "Unknown")
            geo["city"] = data.get("city", "Unknown")
            geo["isp"] = data.get("org", data.get("isp", "Unknown"))
            geo["latitude"] = data.get("latitude", 0.0)
            geo["longitude"] = data.get("longitude", 0.0)
    except Exception:
        pass

    return geo
