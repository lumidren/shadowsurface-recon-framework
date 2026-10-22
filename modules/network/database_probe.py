"""
Database Exposure Scanner
Probes high-risk database ports (MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch) for unauthenticated access.
"""

import socket
from typing import Dict, Any, List

def probe_database_exposure(ip: str, timeout: float = 2.0) -> List[Dict[str, Any]]:
    """Probes databases and reports exposed instances."""
    results = []

    db_checks = [
        {"name": "Redis", "port": 6379, "payload": b"*1\r\n$4\r\nPING\r\n", "expected": b"+PONG"},
        {"name": "Elasticsearch", "port": 9200, "payload": b"GET / HTTP/1.0\r\n\r\n", "expected": b"cluster_name"},
        {"name": "MySQL", "port": 3306, "payload": b"", "expected": b"mysql"},
        {"name": "PostgreSQL", "port": 5432, "payload": b"", "expected": b""},
        {"name": "MongoDB", "port": 27017, "payload": b"\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00", "expected": b"ismaster"}
    ]

    for db in db_checks:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, db["port"])) == 0:
                is_unauth = False
                banner = ""
                if db["payload"]:
                    s.sendall(db["payload"])
                    resp = s.recv(512)
                    banner = resp.decode("utf-8", errors="ignore").strip()
                    if db["expected"].lower() in resp.lower():
                        is_unauth = True

                results.append({
                    "database": db["name"],
                    "port": db["port"],
                    "exposed": True,
                    "unauthenticated_access": is_unauth,
                    "severity": "CRITICAL" if is_unauth else "HIGH"
                })
        except Exception:
            pass
        finally:
            s.close()

    return results
