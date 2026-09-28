from collections.abc import AsyncIterator
from secrets import token_hex
from uuid import uuid4

import pytest
from httpx2 import ASGITransport, AsyncClient
from sqlalchemy import delete

from app.core.config import Settings
from app.main import create_app
from app.models import User
from app.schemas.auth import TokenPairResponse
from app.security.rate_limit import bucket_key

pytestmark = [pytest.mark.integration, pytest.mark.anyio]
PASSWORD = "PUBLIC-TEST-release-journey-123!"
SUMMARY_FIELDS = {"id", "title", "created_at", "updated_at"}


@pytest.fixture
async def journey() -> AsyncIterator[tuple[AsyncClient, str, str]]:
    emails = (f"{uuid4()}@example.com", f"{uuid4()}@example.com")
    settings = Settings(
        rate_limit_secret=token_hex(32),
        login_rate_limit_per_ip=20,
        login_rate_limit_per_account=5,
        register_rate_limit_per_ip=10,
        rate_limit_window_seconds=60,
    )
    application = create_app(settings)
    keys = [
        bucket_key(settings.rate_limit_hmac_key(), "register-ip", "127.0.0.1"),
        bucket_key(settings.rate_limit_hmac_key(), "login-ip", "127.0.0.1"),
        *(
            bucket_key(settings.rate_limit_hmac_key(), "login-account", e)
            for e in emails
        ),
    ]
    async with application.router.lifespan_context(application):
        try:
            async with AsyncClient(
                transport=ASGITransport(app=application), base_url="http://test"
            ) as client:
                yield client, *emails
        finally:
            try:
                async with application.state.session_factory() as db, db.begin():
                    await db.execute(delete(User).where(User.email.in_(emails)))
            finally:
                await application.state.redis.delete(*keys)


def bearer(pair: TokenPairResponse) -> dict[str, str]:
    return {"Authorization": f"Bearer {pair.access_token}"}


async def login(client: AsyncClient, email: str) -> TokenPairResponse:
    response = await client.post(
        "/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert response.status_code == 200
    return TokenPairResponse.model_validate(response.json())


async def exercise_secret(client: AsyncClient, pair: TokenPairResponse) -> str:
    auth = bearer(pair)
    created = await client.post(
        "/secrets",
        headers=auth,
        json={"title": "Release vault", "content": "private-v1"},
    )
    assert created.status_code == 201
    path = f"/secrets/{created.json()['id']}"
    fetched = await client.get(path, headers=auth)
    assert fetched.status_code == 200 and fetched.json()["content"] == "private-v1"
    for query in ({"limit": 1, "offset": 0}, {"q": "Release"}):
        listed = await client.get("/secrets", headers=auth, params=query)
        assert listed.status_code == 200
        page = listed.json()
        assert len(page["items"]) == 1 and page["has_more"] is False
        assert page["items"][0]["id"] == created.json()["id"]
        assert set(page["items"][0]) == SUMMARY_FIELDS
    title = await client.patch(path, headers=auth, json={"title": "Renamed vault"})
    assert title.status_code == 200 and set(title.json()) == SUMMARY_FIELDS
    assert title.json()["title"] == "Renamed vault"
    unchanged = await client.get(path, headers=auth)
    assert unchanged.status_code == 200 and unchanged.json()["content"] == "private-v1"
    content = await client.patch(path, headers=auth, json={"content": "private-v2"})
    assert content.status_code == 200 and set(content.json()) == SUMMARY_FIELDS
    updated = await client.get(path, headers=auth)
    assert updated.status_code == 200 and updated.json()["content"] == "private-v2"
    return path


async def assert_not_found(
    client: AsyncClient, path: str, auth: dict[str, str]
) -> None:
    for method, body in (
        ("GET", None),
        ("PATCH", {"title": "intrusion"}),
        ("DELETE", None),
    ):
        response = await client.request(method, path, headers=auth, json=body)
        assert response.status_code == 404
        assert response.json() == {"detail": "Secret not found."}


async def test_reference_user_journey(journey: tuple[AsyncClient, str, str]) -> None:
    client, email_a, email_b = journey
    for email in (email_a, email_b):
        registered = await client.post(
            "/auth/register", json={"email": email, "password": PASSWORD}
        )
        assert registered.status_code == 201
    first = await login(client, email_a)
    path = await exercise_secret(client, first)
    other = await login(client, email_b)
    await assert_not_found(client, path, bearer(other))
    preserved = await client.get(path, headers=bearer(first))
    assert preserved.status_code == 200
    assert preserved.json()["title"] == "Renamed vault"
    assert preserved.json()["content"] == "private-v2"
    refreshed = await client.post(
        "/auth/refresh", json={"refresh_token": first.refresh_token}
    )
    assert refreshed.status_code == 200
    second = TokenPairResponse.model_validate(refreshed.json())
    assert second.access_token != first.access_token
    assert second.refresh_token != first.refresh_token
    identity = await client.get("/users/me", headers=bearer(second))
    assert identity.status_code == 200 and identity.json()["email"] == email_a
    logout = await client.post(
        "/auth/logout", json={"refresh_token": second.refresh_token}
    )
    assert logout.status_code == 204 and logout.content == b""
    for pair in (first, second):
        for protected in ("/users/me", path):
            denied = await client.get(protected, headers=bearer(pair))
            assert denied.status_code == 401
        denied_refresh = await client.post(
            "/auth/refresh", json={"refresh_token": pair.refresh_token}
        )
        assert denied_refresh.status_code == 401
    # Une nouvelle session légitime permet de supprimer après le logout précédent.
    final = await login(client, email_a)
    deleted = await client.delete(path, headers=bearer(final))
    assert deleted.status_code == 204 and deleted.content == b""
    await assert_not_found(client, path, bearer(final))
    empty = await client.get("/secrets", headers=bearer(final))
    assert empty.status_code == 200 and empty.json()["items"] == []
