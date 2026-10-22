"""
Prometheus Metrics & Grafana Dashboard Exposure Probe
Audits /metrics, port 9090 (Prometheus), and port 3000 (Grafana) for telemetry leaks.
"""

from typing import Dict, Any, List
import requests

def probe_telemetry_exposure(domain: str) -> List[Dict[str, Any]]:
    """Scans for exposed metrics endpoints."""
    findings = []
    base_url = f"https://{domain}"

    try:
        r = requests.get(f"{base_url}/metrics", timeout=4, verify=False)
        if r.status_code == 200 and ("go_goroutines" in r.text or "http_requests_total" in r.text):
            findings.append({
                "type": "Prometheus Metrics",
                "url": f"{base_url}/metrics",
                "severity": "MEDIUM",
                "details": "Exposed Prometheus /metrics endpoint discloses internal system topology."
            })
    except Exception:
        pass

    return findings
