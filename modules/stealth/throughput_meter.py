"""
Network Throughput and Scan Duration Telemetry Tracker
Tracks bandwidth usage, requests per second, and scan phase durations.
"""

import time
from typing import Dict, Any

class TelemetryTracker:
    """Tracks scan timing and request metrics."""
    def __init__(self):
        self.start_time = time.time()
        self.total_requests = 0
        self.phase_times: Dict[str, float] = {}
        self._current_phase_start = 0.0

    def start_phase(self, phase_name: str):
        """Marks the beginning of a recon phase."""
        self._current_phase_start = time.time()

    def end_phase(self, phase_name: str):
        """Records elapsed time for a phase."""
        elapsed = time.time() - self._current_phase_start
        self.phase_times[phase_name] = round(elapsed, 2)

    def record_request(self):
        """Increments request counter."""
        self.total_requests += 1

    def get_summary(self) -> Dict[str, Any]:
        """Returns performance metrics summary."""
        total_duration = time.time() - self.start_time
        rps = (self.total_requests / total_duration) if total_duration > 0 else 0.0
        return {
            "total_duration_seconds": round(total_duration, 2),
            "total_requests": self.total_requests,
            "requests_per_second": round(rps, 2),
            "phase_durations": self.phase_times
        }
