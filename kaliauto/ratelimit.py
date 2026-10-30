"""A token bucket per host, because a scanner that floods is a scanner that hurts."""

from __future__ import annotations

import time
from typing import Callable, Dict


class RateLimiter:
    """At most `per_second` requests to one host, and never two at once globally."""

    def __init__(self, per_second: float = 1.0, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        if per_second <= 0:
            raise ValueError("per_second must be greater than zero")
        self.min_interval = 1.0 / float(per_second)
        self.clock = clock
        self.sleep = sleep
        self._last: Dict[str, float] = {}
        self.total_slept = 0.0

    def wait(self, host: str) -> float:
        now = self.clock()
        last = self._last.get(host)
        if last is not None:
            elapsed = now - last
            if elapsed < self.min_interval:
                delay = self.min_interval - elapsed
                self.sleep(delay)
                self.total_slept += delay
                now = self.clock()
        self._last[host] = now
        return now
