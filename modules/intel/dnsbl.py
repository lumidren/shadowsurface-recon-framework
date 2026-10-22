"""
Public DNS Blackhole List (DNSBL / RBL) Spam Reputation Validator
Queries major spam and malware blacklists (Spamhaus, SORBS, Barracuda) for IP reputation.
"""

from typing import Dict, Any, List
import socket

DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org"
]

def check_dnsbl_reputation(ip: str) -> Dict[str, Any]:
    """Checks if IP is blacklisted in major reputation blocklists."""
    res = {
        "ip": ip,
        "is_blacklisted": False,
        "blacklists_detected": [],
        "total_checks": len(DNSBL_SERVERS)
    }
    if not ip or ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
        return res

    rev_ip = ".".join(reversed(ip.split(".")))
    for rbl in DNSBL_SERVERS:
        query = f"{rev_ip}.{rbl}"
        try:
            resolved = socket.gethostbyname(query)
            if resolved.startswith("127."):
                res["is_blacklisted"] = True
                res["blacklists_detected"].append(rbl)
        except Exception:
            continue

    return res
