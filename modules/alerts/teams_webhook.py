"""
Microsoft Teams Adaptive Card Security Connector
Posts executive security summaries into Microsoft Teams collaboration channels.
"""

from typing import Dict, Any
import requests

def send_teams_alert(webhook_url: str, domain: str, score: int, grade: str) -> bool:
    """Sends MessageCard payload to MS Teams."""
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "0076D7",
        "summary": f"ShadowSurface Recon: {domain}",
        "sections": [{
            "activityTitle": f"🛡️ ShadowSurface Reconnaissance Completed: {domain}",
            "facts": [
                {"name": "Domain", "value": domain},
                {"name": "Posture Score", "value": f"{score}/100"},
                {"name": "Grade", "value": grade}
            ]
        }]
    }
    try:
        r = requests.post(webhook_url, json=payload, timeout=6)
        return r.status_code == 200
    except Exception:
        return False
