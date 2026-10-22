"""
Configuration File & Environment Loader
Loads default settings, proxy configs, API keys, and scope rules from shadowsurface.json / environment.
"""

import os
import json
from typing import Dict, Any

DEFAULT_CONFIG: Dict[str, Any] = {
    "output_dir": "reports",
    "ports_profile": "top20",
    "rate_limit_rps": 10.0,
    "timeout": 4.0,
    "user_agent_rotation": True,
    "api_keys": {
        "abuseipdb": "",
        "urlscan": ""
    },
    "alerts": {
        "slack_webhook": "",
        "discord_webhook": "",
        "teams_webhook": ""
    }
}

def load_framework_config(config_path: str = "shadowsurface.json") -> Dict[str, Any]:
    """Loads configuration merging defaults with custom config file and environment variables."""
    cfg = DEFAULT_CONFIG.copy()

    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
                cfg.update(user_cfg)
        except Exception:
            pass

    # Check env overrides
    if "ABUSEIPDB_API_KEY" in os.environ:
        cfg["api_keys"]["abuseipdb"] = os.environ["ABUSEIPDB_API_KEY"]
    if "SLACK_WEBHOOK_URL" in os.environ:
        cfg["alerts"]["slack_webhook"] = os.environ["SLACK_WEBHOOK_URL"]

    return cfg
