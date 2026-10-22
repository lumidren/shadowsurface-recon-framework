"""
Asset Discovery Timeline & Lifecycle Tracker
Structures historical asset discovery events into a chronologically ordered audit trail.
"""

from typing import List, Dict, Any

class AssetTimeline:
    """Maintains timeline events of asset changes."""
    def __init__(self):
        self.events: List[Dict[str, Any]] = []

    def record_event(self, timestamp: str, event_type: str, asset: str, details: str):
        """Adds an event to the chronological timeline."""
        self.events.append({
            "timestamp": timestamp,
            "type": event_type,
            "asset": asset,
            "details": details
        })

    def get_timeline(self) -> List[Dict[str, Any]]:
        """Returns sorted timeline list."""
        return sorted(self.events, key=lambda x: x["timestamp"], reverse=True)
