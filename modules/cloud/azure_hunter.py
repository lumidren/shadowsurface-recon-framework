"""
Azure Blob Storage Container Exposure Detector
Checks candidate storage accounts for publicly accessible blobs and containers.
"""

from typing import List, Dict, Any
import requests

AZURE_TEMPLATES = [
    "{base}", "{base}storage", "{base}assets", "{base}data", "{base}backup"
]

def hunt_azure_blobs(domain: str) -> List[Dict[str, Any]]:
    """Probes candidate Azure Blob storage accounts."""
    base = domain.split(".")[0].replace("-", "")
    discovered = []

    for tmpl in AZURE_TEMPLATES:
        acc = tmpl.format(base=base)
        url = f"https://{acc}.blob.core.windows.net/?comp=list"
        try:
            r = requests.get(url, timeout=4)
            if r.status_code == 200 and "EnumerationResults" in r.text:
                discovered.append({
                    "provider": "Azure Blob Storage",
                    "account": acc,
                    "url": url,
                    "status": "OPEN_PUBLIC_CONTAINER",
                    "severity": "CRITICAL"
                })
            elif r.status_code == 400 or r.status_code == 403:
                discovered.append({
                    "provider": "Azure Blob Storage",
                    "account": acc,
                    "url": f"https://{acc}.blob.core.windows.net",
                    "status": "EXISTS_PROTECTED",
                    "severity": "INFO"
                })
        except Exception:
            pass

    return discovered
