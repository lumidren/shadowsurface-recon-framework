"""
Multi-Threaded Active DNS Wordlist Brute-Forcer
Resolves candidate subdomains in parallel using thread pools.
"""

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

TOP_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "app", "portal",
    "admin", "cloud", "gateway", "support", "beta", "corp", "test", "jira",
    "git", "gitlab", "jenkins", "auth", "sso", "dashboard", "cdn", "shop"
]

def resolve_host(hostname: str) -> Dict[str, str]:
    """Attempts socket A record lookup."""
    try:
        ip = socket.gethostbyname(hostname)
        return {"hostname": hostname, "ip": ip}
    except Exception:
        return {}

def bruteforce_subdomains(domain: str, wordlist: List[str] = None, max_workers: int = 15) -> List[Dict[str, str]]:
    """Bruteforces subdomains against target using thread pool."""
    words = wordlist if wordlist else TOP_SUBDOMAINS
    clean_domain = domain.strip().lower()
    targets = [f"{w}.{clean_domain}" for w in words]
    discovered = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(resolve_host, targets)
        for res in results:
            if res and res.get("ip"):
                discovered.append(res)

    return discovered
