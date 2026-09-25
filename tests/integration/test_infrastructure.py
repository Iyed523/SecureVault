import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import Settings
from app.db.session import create_engine
from app.infrastructure.redis import create_redis
from app.main import create_app

pytestmark = pytest.mark.integration


@pytest.mark.anyio
async def test_postgres_connection_and_session() -> None:
    engine = create_engine(Settings())
    try:
        async with engine.connect() as connection:
            assert (await connection.execute(text("SELECT 1"))).scalar_one() == 1
        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as session:
            assert (await session.execute(text("SELECT 1"))).scalar_one() == 1
    finally:
        await engine.dispose()


@pytest.mark.anyio
async def test_redis_ping() -> None:
    client = create_redis(Settings())
    try:
        assert await client.ping() is True
    finally:
        await client.aclose()


def test_ready_with_real_services() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "services": {"database": "ok", "redis": "ok"},
    }
