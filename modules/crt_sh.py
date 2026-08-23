"""
ShadowSurface Passive Subdomain Enumeration Module (crt.sh)
Discovers public subdomains passively via Certificate Transparency Logs.
"""

import requests
import re
from typing import List, Set

def enumerate_subdomains_crtsh(domain: str, timeout: int = 8) -> List[str]:
    """Queries crt.sh Certificate Transparency logs to find subdomains."""
    subdomains: Set[str] = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ShadowSurface-OSINT/1.0"
    }

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                # Handle multi-line SAN entries
                names = name_value.split("\n")
                for name in names:
                    clean_name = name.strip().lower()
                    # Remove wildcard prefix
                    if clean_name.startswith("*."):
                        clean_name = clean_name[2:]
                    if clean_name.endswith(domain) and clean_name != domain:
                        subdomains.add(clean_name)
    except Exception:
        # Fallback list for offline demo resiliency
        pass

    # Sort discovered subdomains alphabetically
    return sorted(list(subdomains))
