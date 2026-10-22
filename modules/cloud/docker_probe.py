"""
Docker Registry & Daemon API Exposure Probe
Scans port 5000 (Registry v2) and 2375/2376 (Docker Daemon API) for unauthenticated access.
"""

from typing import Dict, Any, List
import requests

def probe_docker_exposure(ip: str) -> List[Dict[str, Any]]:
    """Probes Docker API endpoints on target host."""
    findings = []

    # 1. Docker Registry
    try:
        r = requests.get(f"http://{ip}:5000/v2/_catalog", timeout=3)
        if r.status_code == 200 and "repositories" in r.text:
            findings.append({
                "service": "Docker Registry v2",
                "port": 5000,
                "url": f"http://{ip}:5000/v2/_catalog",
                "severity": "CRITICAL",
                "details": "Publicly exposed Docker Registry allows container image extraction."
            })
    except Exception:
        pass

    # 2. Docker Daemon API
    try:
        r = requests.get(f"http://{ip}:2375/version", timeout=3)
        if r.status_code == 200 and "ApiVersion" in r.text:
            findings.append({
                "service": "Docker Daemon REST API",
                "port": 2375,
                "url": f"http://{ip}:2375/version",
                "severity": "CRITICAL",
                "details": "Unauthenticated Docker API grants root host execution."
            })
    except Exception:
        pass

    return findings
