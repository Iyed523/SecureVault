import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Literal

from redis.asyncio import Redis
from redis.exceptions import RedisError

Bucket = Literal["login-ip", "login-account", "register-ip"]
NAMESPACE = "securevault:ratelimit:v1:"

SLIDING_WINDOW_SCRIPT = """
local clock = redis.call("TIME")
local now_ms = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local limit = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
redis.call("ZREMRANGEBYSCORE", KEYS[1], "-inf", now_ms - window_ms)
local count = redis.call("ZCARD", KEYS[1])
if count >= limit then
    local oldest = redis.call("ZRANGE", KEYS[1], 0, 0, "WITHSCORES")
    local remaining_ms = tonumber(oldest[2]) + window_ms - now_ms
    return {0, math.max(1, math.ceil(remaining_ms / 1000))}
end
redis.call("ZADD", KEYS[1], now_ms, ARGV[3])
redis.call("PEXPIRE", KEYS[1], window_ms)
return {1, 0}
"""


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int | None


class RateLimiterUnavailable(Exception):
    """Redis cannot evaluate the rate limit."""


def bucket_key(secret: bytes, bucket: Bucket, identifier: str) -> str:
    message = bucket.encode("ascii") + b"\0" + identifier.encode("utf-8")
    digest = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return f"{NAMESPACE}{bucket}:{digest}"


class RateLimiter:
    def __init__(self, redis: Redis, secret: bytes) -> None:
        self._redis = redis
        self._secret = secret

    async def check(
        self, *, bucket: Bucket, identifier: str, limit: int, window_seconds: int
    ) -> RateLimitDecision:
        # Also guard internal callers bypassing Settings.
        if type(limit) is not int or not 1 <= limit <= 100000:
            raise ValueError("Invalid rate limit.")
        if type(window_seconds) is not int or not 1 <= window_seconds <= 86400:
            raise ValueError("Invalid rate limit window.")
        key = bucket_key(self._secret, bucket, identifier)
        try:
            allowed, retry_after = await self._redis.eval(
                SLIDING_WINDOW_SCRIPT,
                1,
                key,
                limit,
                window_seconds * 1000,
                secrets.token_hex(16),
            )
        except RedisError:
            raise RateLimiterUnavailable() from None
        return RateLimitDecision(bool(allowed), None if allowed else int(retry_after))
