"""
FTP Anonymous Login & Banner Exposure Probe
Checks for unauthenticated anonymous FTP access and banner exposure on port 21.
"""

import socket
from typing import Dict, Any

def probe_ftp(ip: str, port: int = 21, timeout: float = 3.0) -> Dict[str, Any]:
    """Tests FTP service for anonymous authentication."""
    res = {
        "ip": ip,
        "port": port,
        "is_open": False,
        "banner": None,
        "anonymous_allowed": False,
        "risk_level": "Low"
    }
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) == 0:
            res["is_open"] = True
            banner = s.recv(512).decode("utf-8", errors="ignore").strip()
            res["banner"] = banner
            
            # Try anonymous login
            s.sendall(b"USER anonymous\r\n")
            r1 = s.recv(256).decode("utf-8", errors="ignore")
            if "331" in r1:
                s.sendall(b"PASS shadow@recon.local\r\n")
                r2 = s.recv(256).decode("utf-8", errors="ignore")
                if "230" in r2:
                    res["anonymous_allowed"] = True
                    res["risk_level"] = "High"
    except Exception:
        pass
    finally:
        s.close()

    return res
