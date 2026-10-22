"""
Environment File & Secret Leak Detector
Scans for exposed configuration files (.env, config.json, docker-compose.yml, web.config).
"""

from typing import Dict, Any, List
import requests

SECRET_PATHS = [
    {"file": ".env", "path": "/.env", "needle": "DB_PASSWORD"},
    {"file": "Environment Backup", "path": "/.env.bak", "needle": "APP_KEY"},
    {"file": "Config JSON", "path": "/config.json", "needle": "database"},
    {"file": "Docker Compose", "path": "/docker-compose.yml", "needle": "version:"},
    {"file": "WordPress Config", "path": "/wp-config.php.bak", "needle": "DB_NAME"},
    {"file": "Web Config", "path": "/web.config", "needle": "<configuration>"}
]

def scan_exposed_secrets(domain: str) -> List[Dict[str, Any]]:
    """Scans for exposed secrets and backup files."""
    exposed = []
    base_url = f"https://{domain}"

    for item in SECRET_PATHS:
        try:
            r = requests.get(f"{base_url}{item['path']}", timeout=4, headers={"User-Agent": "ShadowSurface/2.0"}, verify=False)
            if r.status_code == 200 and (item["needle"].lower() in r.text.lower() or len(r.text) > 15):
                exposed.append({
                    "file": item["file"],
                    "path": item["path"],
                    "url": f"{base_url}{item['path']}",
                    "severity": "CRITICAL",
                    "preview": r.text[:80].strip()
                })
        except Exception:
            pass

    return exposed
