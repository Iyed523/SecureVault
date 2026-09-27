import asyncio
import math
import re
from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from app.core.config import Settings
from app.infrastructure.redis import create_redis
from app.security.rate_limit import SLIDING_WINDOW_SCRIPT, RateLimiter, bucket_key

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


@pytest.fixture
async def bucket() -> AsyncIterator[tuple[Redis, RateLimiter, str, str]]:
    settings = Settings()
    redis = create_redis(settings)
    identifier = f"{uuid4()}@example.com"
    key = bucket_key(settings.rate_limit_hmac_key(), "login-account", identifier)
    try:
        yield redis, RateLimiter(redis, settings.rate_limit_hmac_key()), identifier, key
    finally:
        await redis.delete(key)
        await redis.aclose()


async def test_sliding_window_and_ttl(
    bucket: tuple[Redis, RateLimiter, str, str],
) -> None:
    redis, limiter, identifier, key = bucket
    for _ in range(3):
        result = await limiter.check(
            bucket="login-account", identifier=identifier, limit=3, window_seconds=60
        )
        assert result.allowed and result.retry_after_seconds is None
    before = await redis.zrange(key, 0, -1, withscores=True)
    expiry = await redis.pexpiretime(key)
    result = await limiter.check(
        bucket="login-account", identifier=identifier, limit=3, window_seconds=60
    )
    assert not result.allowed and 1 <= result.retry_after_seconds <= 60
    assert await redis.zrange(key, 0, -1, withscores=True) == before
    assert await redis.zcard(key) == 3
    assert await redis.pexpiretime(key) == expiry
    assert 0 < await redis.pttl(key) <= 60000
    assert all(re.fullmatch(r"[0-9a-f]{32}", member) for member, _ in before)
    await redis.delete(key)
    assert (
        await limiter.check(
            bucket="login-account", identifier=identifier, limit=3, window_seconds=60
        )
    ).allowed


async def test_exact_window_cutoff_is_excluded(
    bucket: tuple[Redis, RateLimiter, str, str],
) -> None:
    redis, _, _, key = bucket
    assert (
        'redis.call("ZREMRANGEBYSCORE", KEYS[1], "-inf", now_ms - window_ms)'
        in SLIDING_WINDOW_SCRIPT
    )
    # One Redis execution fixes the exact boundary; no sleep or second TIME.
    result = await redis.eval(
        """
local clock = redis.call("TIME")
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local window_ms = tonumber(ARGV[1])
local cutoff = now_ms - window_ms
redis.call("ZADD", KEYS[1], cutoff, "at-cutoff", cutoff + 1, "inside")
redis.call("PEXPIRE", KEYS[1], window_ms)
local removed = redis.call("ZREMRANGEBYSCORE", KEYS[1], "-inf", cutoff)
return {removed, redis.call("ZCARD", KEYS[1]),
        redis.call("ZSCORE", KEYS[1], "at-cutoff") == false and 1 or 0}
""",
        1,
        key,
        60000,
    )
    assert result == [1, 1, 1]
    assert await redis.zrange(key, 0, -1) == ["inside"]


async def test_expired_scores_removed_and_retry_uses_oldest(
    bucket: tuple[Redis, RateLimiter, str, str],
) -> None:
    redis, limiter, identifier, key = bucket
    seconds, microseconds = await redis.time()
    now_ms = seconds * 1000 + microseconds // 1000
    # Controlled scores, Redis time only; no waiting for a whole window.
    await redis.zadd(key, {"expired": now_ms - 61000, "oldest": now_ms - 10250})
    await redis.pexpire(key, 60000)
    accepted = await limiter.check(
        bucket="login-account", identifier=identifier, limit=2, window_seconds=60
    )
    assert accepted.allowed
    assert await redis.zscore(key, "expired") is None
    assert await redis.zcard(key) == 2
    before = await redis.time()
    refused = await limiter.check(
        bucket="login-account", identifier=identifier, limit=2, window_seconds=60
    )
    after = await redis.time()
    oldest = now_ms - 10250
    lower = max(
        1, math.ceil((oldest + 60000 - (after[0] * 1000 + after[1] // 1000)) / 1000)
    )
    upper = max(
        1, math.ceil((oldest + 60000 - (before[0] * 1000 + before[1] // 1000)) / 1000)
    )
    assert not refused.allowed
    assert lower <= refused.retry_after_seconds <= upper


async def test_twenty_concurrent_checks_allow_exactly_five(
    bucket: tuple[Redis, RateLimiter, str, str],
) -> None:
    redis, limiter, identifier, key = bucket
    decisions = await asyncio.gather(
        *(
            limiter.check(
                bucket="login-account",
                identifier=identifier,
                limit=5,
                window_seconds=60,
            )
            for _ in range(20)
        )
    )
    assert sum(item.allowed for item in decisions) == 5
    assert sum(not item.allowed for item in decisions) == 15
    assert await redis.zcard(key) == 5
    assert 0 < await redis.pttl(key) <= 60000
