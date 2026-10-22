"""
SSH Service Auditor & Version Security Probe
Connects to TCP port 22 to extract OpenSSH banner, protocol version, and check for high-impact CVEs.
"""

import socket
from typing import Dict, Any

VULNERABLE_SSH_VERSIONS = [
    "OpenSSH_8.5p1", "OpenSSH_8.6p1", "OpenSSH_8.7p1", "OpenSSH_8.8p1",
    "OpenSSH_8.9p1", "OpenSSH_9.0p1", "OpenSSH_9.1p1", "OpenSSH_9.2p1",
    "OpenSSH_9.3p1", "OpenSSH_9.4p1", "OpenSSH_9.5p1", "OpenSSH_9.6p1", "OpenSSH_9.7p1"
]

def probe_ssh_security(ip: str, port: int = 22, timeout: float = 3.0) -> Dict[str, Any]:
    """Audits SSH service on target host."""
    res = {
        "ip": ip,
        "port": port,
        "is_open": False,
        "banner": None,
        "regresshion_vulnerable": False,
        "risk_level": "Low"
    }
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) == 0:
            res["is_open"] = True
            banner = s.recv(256).decode("utf-8", errors="ignore").strip()
            res["banner"] = banner

            for v in VULNERABLE_SSH_VERSIONS:
                if v in banner:
                    res["regresshion_vulnerable"] = True
                    res["risk_level"] = "Critical"
                    res["details"] = f"Potentially vulnerable to regreSSHion (CVE-2024-6387 RCE): {v}"
                    break
    except Exception:
        pass
    finally:
        s.close()

    return res
