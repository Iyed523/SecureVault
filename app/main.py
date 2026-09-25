import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.api.router import router
from app.core.config import Settings
from app.core.logging import configure_logging
from app.db.session import create_engine
from app.infrastructure.redis import create_redis

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    settings = application.state.settings
    configure_logging(settings.log_level)
    engine = create_engine(settings)
    try:
        redis = create_redis(settings)
        try:
            application.state.database_engine = engine
            application.state.session_factory = async_sessionmaker(
                engine, expire_on_commit=False
            )
            application.state.redis = redis
            logger.info("Application démarrée (environnement : %s)", settings.app_env)
            yield
        finally:
            await redis.aclose()
    finally:
        await engine.dispose()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings if settings is not None else Settings()
    application = FastAPI(
        title=settings.app_name, debug=settings.debug, lifespan=lifespan
    )
    application.state.settings = settings
    application.include_router(router)
    return application


app = create_app()
