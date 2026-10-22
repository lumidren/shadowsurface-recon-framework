"""
Continuous Background Daemon Runner & Scheduler
Executes daily or hourly scheduled scans for continuous external attack surface monitoring.
"""

import time
from typing import Callable, Any

class MonitoringDaemon:
    """Daemon runner that executes periodic ASM assessments."""
    def __init__(self, interval_seconds: int = 86400):
        self.interval = interval_seconds
        self.running = False

    def run_loop(self, scan_callback: Callable[[], Any], max_runs: int = None):
        """Runs the scheduled scan callback continuously."""
        self.running = True
        runs = 0
        try:
            while self.running:
                scan_callback()
                runs += 1
                if max_runs and runs >= max_runs:
                    break
                time.sleep(self.interval)
        except KeyboardInterrupt:
            self.running = False
