"""
Enterprise Target Watchlist Manager
Manages batch target lists (domains, IP ranges, organizational boundaries) for scheduled scanning.
"""

from typing import List
import os

class WatchlistManager:
    """Loads and maintains multi-target batch files."""
    def __init__(self, filepath: str = "targets.txt"):
        self.filepath = filepath

    def get_targets(self) -> List[str]:
        """Reads target domains from file."""
        if not os.path.exists(self.filepath):
            return []
        with open(self.filepath, "r", encoding="utf-8") as f:
            lines = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
        return sorted(list(set(lines)))

    def add_target(self, domain: str):
        """Appends a new target domain."""
        clean = domain.strip().lower()
        targets = set(self.get_targets())
        if clean not in targets:
            with open(self.filepath, "a", encoding="utf-8") as f:
                f.write(f"{clean}\n")
