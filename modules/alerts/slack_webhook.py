"""
Slack Incoming Webhook Notification Integration
Sends real-time high-severity vulnerability alerts and scan summaries to Slack channels.
"""

from typing import Dict, Any
import requests

def send_slack_alert(webhook_url: str, title: str, domain: str, score: int, grade: str, findings_count: int) -> bool:
    """Dispatches Slack Block Kit formatted message."""
    payload = {
        "text": f"🛡️ ShadowSurface Alert: {title} for {domain}",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🛡️ ShadowSurface Recon Alert: {domain}"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:* {domain}"},
                    {"type": "mrkdwn", "text": f"*Security Grade:* {grade} ({score}/100)"},
                    {"type": "mrkdwn", "text": f"*Total Findings:* {findings_count}"},
                    {"type": "mrkdwn", "text": f"*Status:* Action Required"}
                ]
            }
        ]
    }
    try:
        r = requests.post(webhook_url, json=payload, timeout=6)
        return r.status_code == 200
    except Exception:
        return False
