"""
Discord Webhook Alert Dispatcher
Formats security findings into rich Discord embeds with color-coded severity.
"""

from typing import Dict, Any
import requests

def send_discord_alert(webhook_url: str, domain: str, score: int, grade: str, critical_count: int) -> bool:
    """Sends rich embed notification to Discord."""
    color = 0x2ecc71 if score >= 80 else (0xe67e22 if score >= 60 else 0xe74c3c)
    embed = {
        "title": f"🛡️ ShadowSurface ASM Report: {domain}",
        "color": color,
        "fields": [
            {"name": "Security Score", "value": f"{score}/100", "inline": True},
            {"name": "Grade", "value": grade, "inline": True},
            {"name": "Critical Alerts", "value": str(critical_count), "inline": True}
        ],
        "footer": {"text": "ShadowSurface EASM Framework"}
    }
    try:
        r = requests.post(webhook_url, json={"embeds": [embed]}, timeout=6)
        return r.status_code in [200, 204]
    except Exception:
        return False
