"""
Multi-Cloud Storage & Attack Surface Exposure Aggregator
Aggregates cloud storage, container, and infrastructure findings into unified risk score.
"""

from typing import Dict, Any, List

def aggregate_cloud_risk(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates cloud-specific exposure risk score."""
    score = 100
    critical_count = 0
    high_count = 0

    for f in findings:
        sev = f.get("severity", "").upper()
        if sev == "CRITICAL":
            critical_count += 1
            score -= 30
        elif sev == "HIGH":
            high_count += 1
            score -= 15
        elif sev == "MEDIUM":
            score -= 5

    score = max(0, score)
    return {
        "cloud_security_score": score,
        "total_cloud_assets": len(findings),
        "critical_exposures": critical_count,
        "high_exposures": high_count,
        "status": "SECURE" if score >= 80 else ("ELEVATED_RISK" if score >= 50 else "CRITICAL_EXPOSURE")
    }
