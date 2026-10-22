"""
Firebase Realtime Database Unauthenticated Access Probe
Tests candidate Firebase endpoints for open read permissions via JSON REST API.
"""

from typing import Dict, Any
import requests

def probe_firebase_database(domain: str) -> Dict[str, Any]:
    """Tests if target has an open Firebase database."""
    base = domain.split(".")[0]
    db_name = f"{base}-default-rtdb"
    url = f"https://{db_name}.firebaseio.com/.json"

    res = {
        "domain": domain,
        "database_tested": db_name,
        "is_exposed": False,
        "severity": "Low"
    }

    try:
        r = requests.get(url, timeout=4)
        if r.status_code == 200 and r.text and "error" not in r.text.lower():
            res["is_exposed"] = True
            res["severity"] = "CRITICAL"
            res["url"] = url
            res["details"] = "Unauthenticated read access granted to Firebase database."
    except Exception:
        pass

    return res
