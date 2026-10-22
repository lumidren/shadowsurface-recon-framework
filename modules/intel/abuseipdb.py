"""
AbuseIPDB IP Reputation & Abuse Confidence Scorer
Queries IP threat intelligence to evaluate malicious report volume and botnet participation.
"""

from typing import Dict, Any
import requests

def check_ip_reputation(ip: str, api_key: str = None) -> Dict[str, Any]:
    """Checks reputation of public IP."""
    res = {
        "ip": ip,
        "abuse_confidence_score": 0,
        "total_reports": 0,
        "is_whitelisted": False,
        "risk_level": "Clean"
    }
    if not ip or ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
        return res

    if not api_key:
        res["note"] = "AbuseIPDB API key not configured; evaluated as unverified clean."
        return res

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get(url, headers=headers, params=params, timeout=5)
        if r.status_code == 200:
            data = r.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            res["abuse_confidence_score"] = score
            res["total_reports"] = data.get("totalReports", 0)
            res["is_whitelisted"] = data.get("isWhitelisted", False)
            if score >= 50:
                res["risk_level"] = "Critical"
            elif score >= 20:
                res["risk_level"] = "Suspicious"
    except Exception:
        pass

    return res
