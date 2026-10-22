"""
Reverse DNS (PTR) Subnet Reconnaissance Module
Performs concurrent reverse DNS pointer sweeps across target IP subnets.
"""

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

def resolve_ptr(ip: str) -> Dict[str, str]:
    """Attempts PTR resolution for a given IP."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return {"ip": ip, "ptr": host}
    except Exception:
        return {}

def sweep_reverse_dns(ip_list: List[str], max_workers: int = 15) -> List[Dict[str, str]]:
    """Resolves PTR records for a list of IP addresses in parallel."""
    discovered = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(resolve_ptr, ip_list)
        for res in results:
            if res and res.get("ptr"):
                discovered.append(res)
    return discovered
