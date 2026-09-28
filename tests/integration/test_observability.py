import io
import json
from uuid import uuid4

import pytest
from httpx2 import AsyncClient

from tests.api.test_observability import assert_headers
from tests.api.test_observability import http_logs as http_logs
from tests.integration.test_secrets import client as client
from tests.integration.test_secrets import settings as settings

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


async def test_sensitive_lifecycle_headers_and_logs(
    client: AsyncClient, http_logs: io.StringIO
) -> None:
    email = f"{uuid4()}@example.com"
    password = "PUBLIC-TEST-PASSWORD-observability-123!"
    title = "PRIVATE-TITLE-SENTINEL"
    content = "PRIVATE-CONTENT-SENTINEL"
    identifiers: list[str] = []

    registration = await client.post(
        "/auth/register", json={"email": email, "password": password}
    )
    assert registration.status_code == 201
    identifiers.append(assert_headers(registration))
    duplicate = await client.post(
        "/auth/register", json={"email": email, "password": password}
    )
    assert duplicate.status_code == 409
    identifiers.append(assert_headers(duplicate))
    logged_in = await client.post(
        "/auth/login", json={"email": email, "password": password}
    )
    assert logged_in.status_code == 200
    identifiers.append(assert_headers(logged_in))
    pair = logged_in.json()
    auth = {"Authorization": f"Bearer {pair['access_token']}"}
    created = await client.post(
        "/secrets", json={"title": title, "content": content}, headers=auth
    )
    assert created.status_code == 201
    identifiers.append(assert_headers(created))
    secret_id = created.json()["id"]
    fetched = await client.get(f"/secrets/{secret_id}", headers=auth)
    assert fetched.status_code == 200 and fetched.json()["content"] == content
    identifiers.append(assert_headers(fetched))
    listed = await client.get("/secrets", params={"q": title}, headers=auth)
    assert listed.status_code == 200
    identifiers.append(assert_headers(listed))
    deleted = await client.delete(f"/secrets/{secret_id}", headers=auth)
    assert deleted.status_code == 204 and deleted.content == b""
    identifiers.append(assert_headers(deleted))
    refreshed = await client.post(
        "/auth/refresh", json={"refresh_token": pair["refresh_token"]}
    )
    assert refreshed.status_code == 200
    identifiers.append(assert_headers(refreshed))
    new_pair = refreshed.json()
    logout = await client.post(
        "/auth/logout", json={"refresh_token": new_pair["refresh_token"]}
    )
    assert logout.status_code == 204 and logout.content == b""
    identifiers.append(assert_headers(logout))
    assert len(set(identifiers)) == len(identifiers)
    output = http_logs.getvalue()
    for value in (
        email,
        password,
        title,
        content,
        secret_id,
        registration.json()["id"],
        pair["access_token"],
        pair["refresh_token"],
        new_pair["access_token"],
        new_pair["refresh_token"],
    ):
        assert value not in output
    records = [json.loads(line) for line in output.splitlines()]
    assert [record["request_id"] for record in records] == identifiers
    assert "/secrets/{secret_id}" in {record["route"] for record in records}
