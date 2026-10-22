"""
HashiCorp Vault & Consul API Exposure Scanner
Detects exposed secrets managers and service discovery APIs (:8200 Vault, :8500 Consul).
"""

from typing import Dict, Any, List
import requests

def probe_vault_consul(ip: str) -> List[Dict[str, Any]]:
    """Probes for exposed Vault and Consul APIs."""
    findings = []

    # Vault
    try:
        r = requests.get(f"http://{ip}:8200/v1/sys/health", timeout=3)
        if r.status_code in [200, 429, 473, 501, 503] and "initialized" in r.text:
            findings.append({
                "service": "HashiCorp Vault",
                "port": 8200,
                "url": f"http://{ip}:8200/v1/sys/health",
                "severity": "HIGH",
                "details": "Exposed HashiCorp Vault secrets management API."
            })
    except Exception:
        pass

    # Consul
    try:
        r = requests.get(f"http://{ip}:8500/v1/status/leader", timeout=3)
        if r.status_code == 200:
            findings.append({
                "service": "HashiCorp Consul",
                "port": 8500,
                "url": f"http://{ip}:8500/v1/status/leader",
                "severity": "HIGH",
                "details": "Exposed HashiCorp Consul cluster consensus API."
            })
    except Exception:
        pass

    return findings
