import asyncio
import logging

import pytest
from asyncpg import PostgresError
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import DisconnectionError, OperationalError
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError

from app.infrastructure.readiness import service_status


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("sensitive-detail"),
        OperationalError(None, None, RuntimeError("sensitive-detail")),
        DisconnectionError("sensitive-detail"),
        SQLAlchemyTimeoutError("sensitive-detail"),
        PostgresError("sensitive-detail"),
        RedisConnectionError("sensitive-detail"),
        ConnectionRefusedError("sensitive-detail"),
    ],
)
def test_expected_failure_is_sanitized(
    error: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    async def check() -> bool:
        raise error

    with caplog.at_level(logging.WARNING):
        assert asyncio.run(service_status(check)) == "unavailable"
    assert "Infrastructure readiness check failed" in caplog.text
    assert "sensitive-detail" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


def test_probe_deadline_cancels_a_blocked_check() -> None:
    cancelled = False

    async def check() -> bool:
        nonlocal cancelled
        try:
            await asyncio.Event().wait()
            return True
        finally:
            cancelled = True

    assert asyncio.run(service_status(check)) == "unavailable"
    assert cancelled


@pytest.mark.parametrize("error", [TypeError("bug"), asyncio.CancelledError()])
def test_unexpected_error_or_cancellation_propagates(error: BaseException) -> None:
    async def check() -> bool:
        raise error

    with pytest.raises(type(error)):
        asyncio.run(service_status(check))
