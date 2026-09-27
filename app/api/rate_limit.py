from typing import Annotated

from fastapi import Depends, HTTPException, Request
from redis.asyncio import Redis

from app.api.dependencies import get_settings
from app.core.config import Settings
from app.infrastructure.redis import get_redis
from app.security.rate_limit import Bucket, RateLimiter, RateLimiterUnavailable


def get_rate_limiter(
    redis: Annotated[Redis, Depends(get_redis)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> RateLimiter:
    return RateLimiter(redis, settings.rate_limit_hmac_key())


def client_identifier(request: Request) -> str:
    return request.client.host if request.client is not None else "unknown"


async def enforce_rate_limit(
    limiter: RateLimiter,
    bucket: Bucket,
    identifier: str,
    limit: int,
    window_seconds: int,
) -> None:
    try:
        decision = await limiter.check(
            bucket=bucket,
            identifier=identifier,
            limit=limit,
            window_seconds=window_seconds,
        )
    except RateLimiterUnavailable:
        raise HTTPException(
            status_code=503, detail="Service temporarily unavailable."
        ) from None
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many requests.",
            headers={"Retry-After": str(decision.retry_after_seconds)},
        )
