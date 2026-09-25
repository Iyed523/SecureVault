import asyncio
from typing import Annotated, Literal, TypedDict

from fastapi import APIRouter, Depends, Response
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine

from app.db.session import get_engine
from app.infrastructure.readiness import (
    ServiceStatus,
    check_database,
    check_redis,
    service_status,
)
from app.infrastructure.redis import get_redis

router = APIRouter()


class ReadinessResponse(TypedDict):
    status: Literal["ready", "not_ready"]
    services: dict[str, ServiceStatus]


@router.get("/ready", responses={503: {"model": ReadinessResponse}})
async def ready(
    response: Response,
    engine: Annotated[AsyncEngine, Depends(get_engine)],
    redis: Annotated[Redis, Depends(get_redis)],
) -> ReadinessResponse:
    database_status, redis_status = await asyncio.gather(
        service_status(lambda: check_database(engine)),
        service_status(lambda: check_redis(redis)),
    )
    available = database_status == redis_status == "ok"
    response.status_code = 200 if available else 503
    return {
        "status": "ready" if available else "not_ready",
        "services": {"database": database_status, "redis": redis_status},
    }
