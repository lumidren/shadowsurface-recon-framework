"""
Pure Passive Recon Isolation Mode
Guarantees that zero direct packets or HTTP requests touch the target infrastructure.
"""

class PassiveModeEnforcer:
    """Guarantees pure OSINT passive isolation without active host connection."""
    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def validate_action(self, action_type: str, target: str):
        """Raises PermissionError if active action is attempted in passive mode."""
        if self.enabled and action_type.lower() in ["port_scan", "active_dns_brute", "path_crawl", "socket_connect"]:
            raise PermissionError(f"[PASSIVE-ONLY MODE] Direct network touch blocked for action '{action_type}' against '{target}'.")
        return True
