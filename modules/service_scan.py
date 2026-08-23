"""
ShadowSurface Service & Port Discovery Module
Performs concurrent TCP socket probing and service banner grabbing for high-value ports.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

# Top High-Value External Exposure Ports
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB / Active Directory",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL Database",
    6379: "Redis (Unauthenticated Cache)",
    8080: "HTTP-Proxy / Jenkins / Tomcat",
    8443: "HTTPS-Alt / Admin Console",
    9200: "Elasticsearch REST API",
    27017: "MongoDB Database"
}

def probe_port(target_ip: str, port: int, service_name: str, timeout: float = 1.5) -> Dict[str, Any]:
    """Tests a single TCP port and grabs available banner."""
    result = {
        "port": port,
        "service": service_name,
        "state": "closed",
        "banner": "",
        "risk_tag": "Informational"
    }

    # Tag potential high-risk exposure
    if port in [445, 3389, 6379, 27017, 9200]:
        result["risk_tag"] = "High Risk (Exposed Internal Service)"
    elif port in [21, 22, 3306, 5432]:
        result["risk_tag"] = "Medium Risk (Direct Management / DB Exposure)"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((target_ip, port)) == 0:
                result["state"] = "open"
                # Attempt light banner grabbing
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner_bytes = sock.recv(256)
                    result["banner"] = banner_bytes.decode("utf-8", errors="ignore").split("\r\n")[0]
                except Exception:
                    pass
    except Exception:
        pass

    return result


def scan_host_services(target_ip: str, max_threads: int = 15) -> List[Dict[str, Any]]:
    """Scans all critical ports concurrently."""
    open_services = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(probe_port, target_ip, port, name): port
            for port, name in COMMON_PORTS.items()
        }

        for future in as_completed(futures):
            try:
                res = future.result()
                if res["state"] == "open":
                    open_services.append(res)
            except Exception:
                pass

    return sorted(open_services, key=lambda x: x["port"])
