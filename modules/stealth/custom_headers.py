"""
Custom HTTP Header Injection & Authorization Token Manager
Allows penetration testers to supply corporate auth headers, cookies, and custom testing tokens.
"""

from typing import Dict, Any

class CustomHeaderManager:
    """Manages custom HTTP header sets for scoped engagements."""
    def __init__(self, default_headers: Dict[str, str] = None):
        self.headers = default_headers.copy() if default_headers else {}

    def set_header(self, name: str, value: str):
        """Sets or overrides an HTTP header."""
        self.headers[name] = value

    def set_auth_bearer(self, token: str):
        """Configures Authorization Bearer token."""
        self.headers["Authorization"] = f"Bearer {token.strip()}"

    def set_custom_cookie(self, cookie_string: str):
        """Configures custom Cookie header."""
        self.headers["Cookie"] = cookie_string.strip()

    def get_headers(self) -> Dict[str, str]:
        """Retrieves compiled headers dict."""
        return self.headers
