"""
Automated Indicator of Compromise (IOC) Feed Extractor
Structures discovered IP addresses, hostnames, domains, and open ports into actionable STIX/IOC datasets.
"""

from typing import Dict, Any, List

def extract_threat_iocs(recon_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts normalized IOCs from full assessment dictionary."""
    iocs = {
        "domains": set(),
        "ipv4_addresses": set(),
        "fqdns": set(),
        "vulnerable_services": []
    }

    target = recon_data.get("target")
    if target:
        iocs["domains"].add(target)

    # Subdomains
    for sub in recon_data.get("subdomains", []):
        iocs["fqdns"].add(sub)

    # DNS IPs
    dns_res = recon_data.get("dns", {})
    for ip in dns_res.get("a_records", []):
        iocs["ipv4_addresses"].add(ip)

    # Open services
    for svc in recon_data.get("services", []):
        if svc.get("state") == "open":
            iocs["vulnerable_services"].append(f"{svc.get('port')}/tcp")

    return {
        "target": target,
        "total_iocs": len(iocs["domains"]) + len(iocs["ipv4_addresses"]) + len(iocs["fqdns"]),
        "domains": sorted(list(iocs["domains"])),
        "ipv4_addresses": sorted(list(iocs["ipv4_addresses"])),
        "fqdns": sorted(list(iocs["fqdns"])),
        "open_ports": sorted(list(set(iocs["vulnerable_services"])))
    }
