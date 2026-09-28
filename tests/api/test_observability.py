import asyncio
import io
import json
import logging
import re
from collections.abc import Iterator
from datetime import datetime
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI, HTTPException, Response
from fastapi.testclient import TestClient
from httpx2 import ASGITransport, AsyncClient
from httpx2 import Response as HTTPResponse

from app.api.middleware import HTTPObservabilityMiddleware
from app.core.logging import HTTP_LOGGER, HTTPJSONFormatter
from app.core.request_context import request_id


@pytest.fixture
def http_logs() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(HTTPJSONFormatter())
    logger = logging.getLogger(HTTP_LOGGER)
    previous = logger.handlers[:], logger.level, logger.propagate
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        yield stream
    finally:
        logger.handlers, logger.level, logger.propagate = previous
        handler.close()


def assert_headers(response: HTTPResponse) -> str:
    headers = response.headers
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    identifier = headers["x-request-id"]
    assert re.fullmatch(r"[0-9a-f]{32}", identifier)
    assert UUID(identifier).version == 4
    return identifier


@pytest.mark.parametrize("status", [200, 204, 401, 404, 409, 422, 429, 500, 503])
def test_headers_and_contracts(status: int, http_logs: io.StringIO) -> None:
    app = FastAPI()
    app.add_middleware(HTTPObservabilityMiddleware)

    @app.get("/controlled")
    async def controlled() -> Response:
        if status >= 400:
            raise HTTPException(status, "Unchanged", headers={"Retry-After": "60"})
        return Response(status_code=status)

    with TestClient(app) as client:
        response = client.get("/controlled", headers={"X-Request-ID": "CLIENT-ID"})
    identifier = assert_headers(response)
    assert identifier != "CLIENT-ID"
    assert response.status_code == status
    if status >= 400:
        assert response.json() == {"detail": "Unchanged"}
        assert response.headers["retry-after"] == "60"
    else:
        assert response.content == b""
    record = json.loads(http_logs.getvalue())
    assert record["request_id"] == identifier
    assert record["status_code"] == status
    assert record["level"] == "INFO"
    assert record["duration_ms"] >= 0
    assert request_id.get() is None


def test_formatter_allowlist_and_confidentiality() -> None:
    sentinels = {
        key: f"PRIVATE-{key}-SENTINEL"
        for key in (
            "password",
            "password_hash",
            "access_token",
            "refresh_token",
            "content",
            "email",
            "ip",
            "query_title",
            "encryption_key",
            "rate_limit_key",
            "rate_limit_secret",
            "user_id",
            "session_id",
            "secret_id",
            "headers",
        )
    }
    record = logging.LogRecord(
        HTTP_LOGGER, logging.INFO, "private.py", 1, str(sentinels), (), None
    )
    record.__dict__.update(sentinels)
    record.method = "GET"
    record.route = '/constant/"escaped"'
    record.status_code = 200
    record.duration_ms = 1.25
    record.exc_text = "PRIVATE-TRACEBACK-SENTINEL"
    token = request_id.set(uuid4().hex)
    try:
        output = HTTPJSONFormatter().format(record)
        result = json.loads(output)
        assert result["request_id"] == request_id.get()
    finally:
        request_id.reset(token)
    assert set(result) == {
        "timestamp",
        "level",
        "logger",
        "event",
        "request_id",
        "method",
        "route",
        "status_code",
        "duration_ms",
    }
    assert datetime.fromisoformat(result["timestamp"]).utcoffset().total_seconds() == 0
    assert isinstance(result["duration_ms"], float)
    assert result["route"] == record.route
    assert all(value not in output for value in sentinels.values())
    assert "PRIVATE-TRACEBACK-SENTINEL" not in output
    assert "private.py" not in output


@pytest.mark.anyio
async def test_concurrent_context_isolation_and_reset(http_logs: io.StringIO) -> None:
    app = FastAPI()
    app.add_middleware(HTTPObservabilityMiddleware)
    entered = 0
    barrier = asyncio.Event()
    observed: list[str] = []

    @app.get("/concurrent")
    async def concurrent() -> dict[str, str | None]:
        nonlocal entered
        before = request_id.get()
        assert before is not None
        entered += 1
        if entered == 8:
            barrier.set()
        await barrier.wait()
        assert request_id.get() == before
        observed.append(before)
        return {"id": before}

    parent = request_id.set("parent-context")
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            responses = await asyncio.wait_for(
                asyncio.gather(*(client.get("/concurrent") for _ in range(8))), 10
            )
            # Same task, successive requests also restore the caller context.
            for _ in range(2):
                responses.append(await client.get("/concurrent"))
                assert request_id.get() == "parent-context"
        identifiers = [assert_headers(response) for response in responses]
        assert len(set(identifiers)) == 10
        assert sorted(identifiers) == sorted(observed)
        assert [response.json()["id"] for response in responses] == identifiers
        records = [json.loads(line) for line in http_logs.getvalue().splitlines()]
        assert sorted(record["request_id"] for record in records) == sorted(identifiers)
    finally:
        request_id.reset(parent)


@pytest.mark.anyio
async def test_unhandled_exception_propagates_and_resets(
    http_logs: io.StringIO,
) -> None:
    app = FastAPI()
    app.add_middleware(HTTPObservabilityMiddleware)

    @app.get("/bug")
    async def bug() -> None:
        raise TypeError("PRIVATE-EXCEPTION-SENTINEL")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        with pytest.raises(TypeError, match="PRIVATE-EXCEPTION-SENTINEL"):
            await client.get("/bug")
    assert request_id.get() is None
    assert "PRIVATE-EXCEPTION-SENTINEL" not in http_logs.getvalue()
    assert json.loads(http_logs.getvalue())["status_code"] == 500


def test_templates_and_unmatched_paths(http_logs: io.StringIO) -> None:
    from app.main import create_app

    app = create_app()
    concrete_id = str(uuid4())
    with TestClient(app) as client:
        for path in (
            "/secrets?q=PRIVATE-TITLE-SENTINEL",
            f"/secrets/{concrete_id}",
            "/PRIVATE-UNKNOWN-PATH",
        ):
            assert_headers(
                client.get(path, headers={"Authorization": "Bearer PRIVATE-TOKEN"})
            )
        assert_headers(client.post("/auth/login", json={"password": "PRIVATE-BODY"}))
    output = http_logs.getvalue()
    records = [json.loads(line) for line in output.splitlines()]
    assert [record["route"] for record in records] == [
        "/secrets",
        "/secrets/{secret_id}",
        "<unmatched>",
        "/auth/login",
    ]
    for value in (concrete_id, "PRIVATE-", "?q=", "Bearer"):
        assert value not in output


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
