"""
Target Scope Manager with CIDR & Host Blacklisting / Whitelisting
Enforces ethical rules of engagement by preventing out-of-scope probes.
"""

import ipaddress
from typing import List

class ScopeManager:
    """Enforces engagement scope boundaries."""
    def __init__(self, allowed_domains: List[str] = None, blacklist_cidrs: List[str] = None):
        self.allowed_domains = allowed_domains if allowed_domains else []
        self.blacklist_cidrs = [ipaddress.ip_network(c) for c in (blacklist_cidrs or [])]

    def is_ip_allowed(self, ip_str: str) -> bool:
        """Checks if IP is not within blacklisted networks."""
        try:
            ip = ipaddress.ip_address(ip_str)
            for net in self.blacklist_cidrs:
                if ip in net:
                    return False
            return True
        except ValueError:
            return False

    def is_host_allowed(self, hostname: str) -> bool:
        """Verifies if hostname belongs to authorized engagement domain."""
        if not self.allowed_domains:
            return True
        clean = hostname.strip().lower()
        return any(clean == d or clean.endswith(f".{d}") for d in self.allowed_domains)
