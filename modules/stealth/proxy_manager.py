"""
HTTP and SOCKS5 Proxy Rotation & Health Validator
Manages proxy lists, validates upstream egress IP, and handles proxy rotation for evasive scans.
"""

from typing import List, Dict, Any, Optional
import requests

class ProxyManager:
    """Handles proxy rotation and connectivity verification."""
    def __init__(self, proxies: List[str] = None):
        self.proxies = proxies if proxies else []
        self.current_idx = 0

    def get_proxy(self) -> Optional[Dict[str, str]]:
        """Returns next available proxy dictionary."""
        if not self.proxies:
            return None
        proxy_url = self.proxies[self.current_idx % len(self.proxies)]
        self.current_idx += 1
        return {"http": proxy_url, "https": proxy_url}

    def verify_proxy(self, proxy_url: str, timeout: int = 5) -> bool:
        """Verifies if proxy is alive and responsive."""
        try:
            r = requests.get("https://api.ipify.org?format=json", proxies={"http": proxy_url, "https": proxy_url}, timeout=timeout)
            return r.status_code == 200
        except Exception:
            return False
