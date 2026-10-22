"""
AlienVault OTX Passive DNS Intelligence Module
Queries AlienVault Open Threat Exchange passive DNS indicators for domain assets.
"""

import requests
from typing import List, Dict, Any

OTX_URL_TEMPLATE = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

def query_alienvault_otx(domain: str, timeout: int = 10) -> List[Dict[str, Any]]:
    """
    Fetches passive DNS records from AlienVault OTX.
    Returns list of records with hostname, address, record_type, first/last seen.
    """
    results = []
    clean_domain = domain.strip().lower()
    headers = {"User-Agent": "ShadowSurface-EASM-Recon/2.0"}

    try:
        url = OTX_URL_TEMPLATE.format(domain=clean_domain)
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            for record in data.get("passive_dns", []):
                hostname = record.get("hostname", "").strip().lower()
                if hostname.endswith(clean_domain):
                    results.append({
                        "hostname": hostname,
                        "address": record.get("address", ""),
                        "record_type": record.get("record_type", ""),
                        "first": record.get("first", ""),
                        "last": record.get("last", "")
                    })
    except Exception:
        pass

    return results
