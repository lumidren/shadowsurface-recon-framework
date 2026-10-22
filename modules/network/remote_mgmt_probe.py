"""
Remote Management Exposure Auditor
Detects internet-exposed administrative interfaces (RDP, VNC, Telnet, WinRM, Kubernetes API).
"""

import socket
from typing import Dict, Any, List

MGMT_PORTS = [
    {"name": "RDP (Remote Desktop)", "port": 3389, "risk": "High"},
    {"name": "VNC Remote Display", "port": 5900, "risk": "High"},
    {"name": "Telnet (Cleartext)", "port": 23, "risk": "Critical"},
    {"name": "WinRM HTTP", "port": 5985, "risk": "High"},
    {"name": "WinRM HTTPS", "port": 5986, "risk": "Medium"},
    {"name": "Kubernetes API Server", "port": 6443, "risk": "Critical"},
    {"name": "Kubelet API", "port": 10250, "risk": "Critical"}
]

def audit_remote_management(ip: str, timeout: float = 1.5) -> List[Dict[str, Any]]:
    """Identifies exposed remote management services."""
    exposed = []
    for svc in MGMT_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, svc["port"])) == 0:
                exposed.append({
                    "service": svc["name"],
                    "port": svc["port"],
                    "risk_level": svc["risk"],
                    "recommendation": "Restrict to internal VPN or bastion host via firewall rules."
                })
        except Exception:
            pass
        finally:
            s.close()
    return exposed
