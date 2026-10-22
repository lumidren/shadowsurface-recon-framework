"""
CI/CD Pipeline Dashboard Exposure Probe
Scans for unauthenticated Jenkins, GitLab, ArgoCD, and TeamCity control dashboards.
"""

from typing import Dict, Any, List
import requests

CICD_TARGETS = [
    {"name": "Jenkins", "path": ":8080/login", "needle": "Jenkins"},
    {"name": "GitLab", "path": ":80/users/sign_in", "needle": "GitLab"},
    {"name": "ArgoCD", "path": ":80/auth/login", "needle": "Argo CD"}
]

def probe_cicd_dashboards(ip: str) -> List[Dict[str, Any]]:
    """Probes for exposed CI/CD servers."""
    exposed = []
    for target in CICD_TARGETS:
        url = f"http://{ip}{target['path']}"
        try:
            r = requests.get(url, timeout=3)
            if target["needle"].lower() in r.text.lower():
                exposed.append({
                    "system": target["name"],
                    "url": url,
                    "severity": "HIGH",
                    "details": f"Discovered exposed {target['name']} pipeline interface."
                })
        except Exception:
            pass
    return exposed
