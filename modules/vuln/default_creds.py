"""
Default Administrative Portal & Unauthenticated Setup Page Detector
Detects exposed phpMyAdmin, Tomcat Web Application Manager, phpinfo(), and default setup wizards.
"""

from typing import List, Dict, Any
import requests

PORTAL_SIGNATURES = [
    {"name": "phpMyAdmin", "path": "/phpmyadmin/", "needle": "phpmyadmin"},
    {"name": "Tomcat Manager", "path": "/manager/html", "needle": "tomcat"},
    {"name": "PHPInfo Exposure", "path": "/phpinfo.php", "needle": "php version"},
    {"name": "WordPress Setup", "path": "/wp-admin/install.php", "needle": "setup configuration"}
]

def detect_default_portals(domain: str) -> List[Dict[str, Any]]:
    """Probes for exposed administrative setup interfaces."""
    findings = []
    base_url = f"https://{domain}"

    for portal in PORTAL_SIGNATURES:
        try:
            r = requests.get(f"{base_url}{portal['path']}", timeout=4, verify=False)
            if portal["needle"] in r.text.lower() and r.status_code in [200, 401]:
                findings.append({
                    "portal": portal["name"],
                    "url": f"{base_url}{portal['path']}",
                    "status_code": r.status_code,
                    "severity": "HIGH",
                    "details": f"Discovered exposed {portal['name']} endpoint."
                })
        except Exception:
            pass

    return findings
