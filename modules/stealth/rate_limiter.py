"""
Request Throttling, Jitter & Adaptive Rate Limiter
Enforces maximum requests-per-second and injects randomized millisecond jitter to evade WAF rate limits.
"""

import time
import random

class AdaptiveRateLimiter:
    """Controls request pacing with randomized jitter."""
    def __init__(self, requests_per_sec: float = 10.0, jitter_range: tuple = (0.05, 0.25)):
        self.interval = 1.0 / max(requests_per_sec, 0.1)
        self.jitter_range = jitter_range
        self.last_request_time = 0.0

    def wait(self):
        """Pauses execution to enforce rate limit and jitter."""
        now = time.time()
        elapsed = now - self.last_request_time
        sleep_needed = self.interval - elapsed
        if sleep_needed > 0:
            time.sleep(sleep_needed)
        # Apply jitter
        jitter = random.uniform(*self.jitter_range)
        time.sleep(jitter)
        self.last_request_time = time.time()
