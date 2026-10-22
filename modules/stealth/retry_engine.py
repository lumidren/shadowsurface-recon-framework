"""
Resilient Network Execution Engine with Exponential Backoff
Executes network actions with automatic retries and exponential delay backoff.
"""

import time
from typing import Callable, Any

def retry_with_backoff(fn: Callable[[], Any], max_retries: int = 3, base_delay: float = 1.0) -> Any:
    """Executes a function with exponential retry logic on failure."""
    last_err = None
    for attempt in range(max_retries):
        try:
            return fn()
        except Exception as e:
            last_err = e
            sleep_time = base_delay * (2 ** attempt)
            time.sleep(sleep_time)
    raise last_err
