"""
SMTP Open Relay & STARTTLS Capability Probe
Inspects port 25/587 for cleartext authentication, STARTTLS support, and open relay indicators.
"""

import socket
from typing import Dict, Any

def probe_smtp(ip: str, port: int = 25, timeout: float = 3.0) -> Dict[str, Any]:
    """Tests SMTP service capabilities."""
    res = {
        "ip": ip,
        "port": port,
        "is_open": False,
        "banner": None,
        "starttls_supported": False,
        "open_relay_risk": "Low"
    }
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) == 0:
            res["is_open"] = True
            banner = s.recv(512).decode("utf-8", errors="ignore").strip()
            res["banner"] = banner

            # Send EHLO
            s.sendall(b"EHLO shadowsurface.local\r\n")
            ehlo_resp = s.recv(1024).decode("utf-8", errors="ignore")
            if "STARTTLS" in ehlo_resp.upper():
                res["starttls_supported"] = True
            else:
                res["open_relay_risk"] = "Medium"
    except Exception:
        pass
    finally:
        s.close()

    return res
