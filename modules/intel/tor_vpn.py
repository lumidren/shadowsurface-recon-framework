"""
Tor Exit Node & Public VPN Relay Detector
Cross-references IP addresses against known public Tor exit nodes and proxy networks.
"""

from typing import Dict, Any
import socket

def check_tor_exit_node(ip: str) -> Dict[str, Any]:
    """Tests if IP is an active Tor exit node using Tor Project DNSBL."""
    res = {
        "ip": ip,
        "is_tor_exit_node": False,
        "details": "Standard IP infrastructure"
    }
    if not ip or ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
        return res

    try:
        rev_ip = ".".join(reversed(ip.split(".")))
        query_host = f"{rev_ip}.dnsel.torproject.org"
        resolved = socket.gethostbyname(query_host)
        if resolved == "127.0.0.2":
            res["is_tor_exit_node"] = True
            res["details"] = "Host IP is a registered Tor exit relay node."
    except Exception:
        pass

    return res
