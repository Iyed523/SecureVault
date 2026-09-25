from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import OperationalError

from app.api.routes import ready
from app.main import create_app


@pytest.mark.parametrize(
    ("database_ok", "redis_ok"), [(False, True), (True, False), (False, False)]
)
def test_ready_returns_sanitized_503(
    monkeypatch: pytest.MonkeyPatch, database_ok: bool, redis_ok: bool
) -> None:
    database_error = OperationalError(
        None, None, RuntimeError("private-password-in-connection-url")
    )
    redis_error = RedisConnectionError("private-password-in-connection-url")
    monkeypatch.setattr(
        ready,
        "check_database",
        AsyncMock(
            return_value=True, side_effect=None if database_ok else database_error
        ),
    )
    monkeypatch.setattr(
        ready,
        "check_redis",
        AsyncMock(return_value=True, side_effect=None if redis_ok else redis_error),
    )
    with TestClient(create_app()) as client:
        response = client.get("/ready")
        health = client.get("/health")
    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "services": {
            "database": "ok" if database_ok else "unavailable",
            "redis": "ok" if redis_ok else "unavailable",
        },
    }
    assert "private-password" not in response.text
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}


def test_ready_propagates_programming_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ready, "check_database", AsyncMock(side_effect=TypeError("bug"))
    )
    monkeypatch.setattr(ready, "check_redis", AsyncMock(return_value=True))
    with TestClient(create_app()) as client, pytest.raises(TypeError, match="bug"):
        client.get("/ready")
