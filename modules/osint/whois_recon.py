"""
WHOIS & Registrar Intelligence Extractor
Extracts registration dates, registrar, and contact info via ICANN RDAP protocol.
"""

import requests
from typing import Dict, Any

RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"

def lookup_whois_rdap(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Performs RDAP WHOIS lookup for the target domain.
    """
    clean_domain = domain.strip().lower()
    info = {
        "domain": clean_domain,
        "registrar": "Unknown",
        "created_date": None,
        "expiry_date": None,
        "status": [],
        "nameservers": []
    }

    try:
        url = RDAP_BOOTSTRAP.format(domain=clean_domain)
        resp = requests.get(url, headers={"Accept": "application/rdap+json"}, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            # Entities -> Registrar
            for ent in data.get("entities", []):
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for entry in vcard[1]:
                            if entry[0] == "fn":
                                info["registrar"] = entry[3]
                                break

            # Events -> created/expired
            for ev in data.get("events", []):
                action = ev.get("eventAction")
                date = ev.get("eventDate")
                if action == "registration":
                    info["created_date"] = date
                elif action == "expiration":
                    info["expiry_date"] = date

            info["status"] = data.get("status", [])
            for ns in data.get("nameservers", []):
                ldh = ns.get("ldhName")
                if ldh:
                    info["nameservers"].append(ldh.lower())
    except Exception:
        pass

    return info
