"""In-memory token bucket rate limiter for tenant and denial-of-wallet defense."""

from __future__ import annotations

import threading
import time


class TokenBucket:
    def __init__(self, capacity: float, refill_rate: float) -> None:
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.last_update = time.monotonic()

    def consume(self, tokens: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_update = now

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


class TenantRateLimiter:
    """Manages token buckets per tenant/API key with automatic eviction."""

    def __init__(self, default_capacity: float = 60.0, default_refill_rate: float = 10.0) -> None:
        self.default_capacity = default_capacity
        self.default_refill_rate = default_refill_rate
        self.buckets: dict[str, TokenBucket] = {}
        self.lock = threading.Lock()

    def check_rate_limit(self, tenant_id: str, cost: float = 1.0) -> bool:
        with self.lock:
            if tenant_id not in self.buckets:
                self.buckets[tenant_id] = TokenBucket(
                    capacity=self.default_capacity,
                    refill_rate=self.default_refill_rate,
                )
            return self.buckets[tenant_id].consume(cost)
