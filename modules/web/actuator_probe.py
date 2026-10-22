"""
Spring Boot Actuator & Microservice Health Audit
Scans for unauthenticated Spring Boot actuator endpoints (/actuator/env, /actuator/heapdump, /actuator/health).
"""

from typing import Dict, Any, List
import requests

ACTUATOR_ENDPOINTS = [
    {"path": "/actuator", "risk": "Medium"},
    {"path": "/actuator/health", "risk": "Low"},
    {"path": "/actuator/env", "risk": "Critical"},
    {"path": "/actuator/beans", "risk": "High"},
    {"path": "/actuator/heapdump", "risk": "Critical"},
    {"path": "/actuator/metrics", "risk": "Medium"}
]

def probe_spring_actuators(domain: str) -> List[Dict[str, Any]]:
    """Probes for exposed Spring Boot Actuator endpoints."""
    leaked = []
    base_url = f"https://{domain}"

    for item in ACTUATOR_ENDPOINTS:
        try:
            r = requests.get(f"{base_url}{item['path']}", timeout=4, headers={"User-Agent": "ShadowSurface/2.0"}, verify=False)
            if r.status_code == 200 and ("actuator" in r.text or "status" in r.text or "UP" in r.text):
                leaked.append({
                    "endpoint": item["path"],
                    "url": f"{base_url}{item['path']}",
                    "risk_level": item["risk"],
                    "status_code": r.status_code
                })
        except Exception:
            pass

    return leaked
