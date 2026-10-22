"""
HackerTarget Passive Subdomain OSINT Module
Queries public HackerTarget hostsearch API to enumerate public subdomains and host IPs.
"""

import requests
from typing import List, Dict, Any

HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q="

def query_hackertarget(domain: str, timeout: int = 8) -> List[Dict[str, str]]:
    """
    Queries HackerTarget hostsearch endpoint for subdomains and IP addresses.
    Returns a list of dicts: [{'hostname': 'sub.domain.com', 'ip': '1.2.3.4'}]
    """
    records = []
    clean_domain = domain.strip().lower()
    headers = {"User-Agent": "ShadowSurface-EASM-Recon/2.0"}

    try:
        resp = requests.get(f"{HACKERTARGET_URL}{clean_domain}", headers=headers, timeout=timeout)
        if resp.status_code == 200 and resp.text:
            lines = resp.text.strip().splitlines()
            for line in lines:
                if "," in line:
                    parts = line.strip().split(",", 1)
                    host = parts[0].strip().lower()
                    ip = parts[1].strip() if len(parts) > 1 else ""
                    if host.endswith(clean_domain) and host != clean_domain:
                        records.append({"hostname": host, "ip": ip})
    except Exception:
        pass

    return records
