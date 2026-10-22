"""
URLScan.io Passive Subdomain Discovery Module
Leverages historical website scans to discover hostnames and shadow endpoints.
"""

import requests
from typing import List

URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"

def query_urlscan(domain: str, timeout: int = 10) -> List[str]:
    """
    Queries URLScan public search API for hostnames linked to the domain.
    """
    hosts = set()
    clean_domain = domain.strip().lower()
    headers = {"User-Agent": "ShadowSurface-EASM-Recon/2.0"}

    try:
        url = URLSCAN_SEARCH_URL.format(domain=clean_domain)
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("results", []):
                page_info = item.get("page", {})
                host = page_info.get("domain", "").strip().lower()
                if host.endswith(clean_domain):
                    hosts.add(host)
    except Exception:
        pass

    return sorted(list(hosts))
