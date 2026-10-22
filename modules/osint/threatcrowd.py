"""
ThreatCrowd Threat Intelligence & Subdomain Discovery Module
Queries ThreatCrowd search API for known infrastructure relationships.
"""

import requests
from typing import List

THREATCROWD_API = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="

def query_threatcrowd(domain: str, timeout: int = 10) -> List[str]:
    """
    Queries ThreatCrowd API for subdomains mapped to target domain.
    """
    subdomains = set()
    clean_domain = domain.strip().lower()
    headers = {"User-Agent": "ShadowSurface-EASM-Recon/2.0"}

    try:
        resp = requests.get(f"{THREATCROWD_API}{clean_domain}", headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            raw_subs = data.get("subdomains", [])
            for sub in raw_subs:
                sub_clean = sub.strip().lower()
                if sub_clean.endswith(clean_domain):
                    subdomains.add(sub_clean)
    except Exception:
        pass

    return sorted(list(subdomains))
