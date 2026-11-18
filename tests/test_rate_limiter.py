"""Tests for token-bucket rate limiting."""

from src.guardrails.rate_limiter import TenantRateLimiter, TokenBucket


def test_token_bucket_consume_and_exhaustion() -> None:
    bucket = TokenBucket(capacity=3.0, refill_rate=1.0)
    assert bucket.consume(1.0) is True
    assert bucket.consume(1.0) is True
    assert bucket.consume(1.0) is True
    # Capacity exhausted
    assert bucket.consume(1.0) is False


def test_tenant_rate_limiter_isolation() -> None:
    limiter = TenantRateLimiter(default_capacity=2.0, default_refill_rate=0.5)

    assert limiter.check_rate_limit("tenant-A", cost=1.0) is True
    assert limiter.check_rate_limit("tenant-A", cost=1.0) is True
    assert limiter.check_rate_limit("tenant-A", cost=1.0) is False

    # Tenant-B should be independent and succeed
    assert limiter.check_rate_limit("tenant-B", cost=1.0) is True
