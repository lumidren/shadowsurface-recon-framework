"""
RapidDNS & Anubis OSINT Aggregator
Extracts publicly indexed subdomains from RapidDNS search.
"""

import re
import requests
from typing import List

RAPIDDNS_URL = "https://rapiddns.io/subdomain/{domain}?page=1"

def query_rapiddns(domain: str, timeout: int = 10) -> List[str]:
    """
    Extracts discovered subdomains from RapidDNS HTML table.
    """
    discovered = set()
    clean_domain = domain.strip().lower()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ShadowSurface/2.0"}

    try:
        url = RAPIDDNS_URL.format(domain=clean_domain)
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            pattern = re.compile(rf'([a-zA-Z0-9_\-\.]+\.{re.escape(clean_domain)})', re.IGNORECASE)
            matches = pattern.findall(resp.text)
            for match in matches:
                discovered.add(match.strip().lower())
    except Exception:
        pass

    return sorted(list(discovered))
