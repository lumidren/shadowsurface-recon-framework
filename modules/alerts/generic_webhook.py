"""
Generic JSON Webhook Dispatcher with HMAC Signature Auth
Sends structured JSON events to SIEM/SOAR platforms (Splunk, Elastic, Cortex XSOAR).
"""

import hmac
import hashlib
import json
import requests
from typing import Dict, Any

def dispatch_generic_webhook(url: str, data: Dict[str, Any], secret_key: str = None) -> bool:
    """Dispatches JSON payload with optional HMAC SHA-256 signature."""
    body_bytes = json.dumps(data).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "ShadowSurface-Notifier/2.0"}

    if secret_key:
        signature = hmac.new(secret_key.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
        headers["X-ShadowSurface-Signature"] = signature

    try:
        r = requests.post(url, data=body_bytes, headers=headers, timeout=6)
        return r.status_code in [200, 201, 202, 204]
    except Exception:
        return False
