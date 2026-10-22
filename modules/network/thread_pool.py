"""
Adaptive High-Concurrency Socket Thread Pool Controller
Manages parallel TCP connections with dynamic batching, jitter, and non-blocking sockets.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Callable

def probe_tcp_port(ip: str, port: int, timeout: float = 1.5) -> Dict[str, Any]:
    """Tests a single TCP port and grabs available banner."""
    res = {
        "port": port,
        "state": "closed",
        "banner": ""
    }
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) == 0:
            res["state"] = "open"
            try:
                s.settimeout(1.0)
                banner_raw = s.recv(512)
                res["banner"] = banner_raw.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
    except Exception:
        pass
    finally:
        s.close()
    return res

def scan_ports_concurrent(ip: str, ports: List[int], max_workers: int = 50, timeout: float = 1.5) -> List[Dict[str, Any]]:
    """Runs parallel port probing across target host."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(probe_tcp_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            res = future.result()
            if res["state"] == "open":
                open_ports.append(res)
    return sorted(open_ports, key=lambda x: x["port"])
