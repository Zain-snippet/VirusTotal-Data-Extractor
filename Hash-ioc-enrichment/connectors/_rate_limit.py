"""Thread-safe rate limiter for API connectors.

Each connector creates its own RateLimiter instance with the desired
minimum interval between calls.  The .wait() method is safe to call
from multiple threads — only one thread passes through the sleep gate
at a time.
"""

import threading
import time


class RateLimiter:
    """Enforce a minimum interval between successive calls."""

    def __init__(self, interval: float) -> None:
        self._interval = interval
        self._last_call: float = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        """Block if needed so that at least *interval* seconds have
        elapsed since the last call returned."""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_call
            if elapsed < self._interval:
                time.sleep(self._interval - elapsed)
            self._last_call = time.time()
