import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Literal

from asyncpg import PostgresError
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, DisconnectionError
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
from sqlalchemy.ext.asyncio import AsyncEngine

type ServiceStatus = Literal["ok", "unavailable"]
logger = logging.getLogger(__name__)


async def check_database(engine: AsyncEngine) -> bool:
    async with engine.connect() as connection:
        return (await connection.execute(text("SELECT 1"))).scalar_one() == 1


async def check_redis(client: Redis) -> bool:
    return bool(await client.ping())


async def service_status(check: Callable[[], Awaitable[bool]]) -> ServiceStatus:
    try:
        async with asyncio.timeout(3):
            if await check():
                return "ok"
    except (
        TimeoutError,
        DBAPIError,
        DisconnectionError,
        SQLAlchemyTimeoutError,
        PostgresError,
        RedisError,
        OSError,
    ):
        # Message constant : aucun contenu d'exception ni détail de connexion.
        logger.warning("Infrastructure readiness check failed")
        return "unavailable"
    logger.warning("Infrastructure readiness check returned a negative result")
    return "unavailable"
