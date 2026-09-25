from typing import cast

from fastapi import Request
from redis.asyncio import Redis

from app.core.config import Settings


def create_redis(settings: Settings) -> Redis:
    return Redis.from_url(
        str(settings.redis_url),
        decode_responses=True,
        socket_connect_timeout=3,
        socket_timeout=3,
    )


def get_redis(request: Request) -> Redis:
    return cast(Redis, request.app.state.redis)
