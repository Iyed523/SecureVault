import json
import logging
from collections.abc import AsyncIterator
from uuid import UUID, uuid4

import pytest
from email_validator import deliverability
from httpx2 import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.main import create_app
from app.models import User
from app.security.passwords import verify_password
from app.services import registration

pytestmark = [pytest.mark.integration, pytest.mark.anyio]
PASSWORD = "  Mot de passe fictif API 🔐  "


@pytest.fixture
async def registration_client(db_session: AsyncSession) -> AsyncIterator[AsyncClient]:
    async def session_override() -> AsyncIterator[AsyncSession]:
        yield db_session

    application = create_app()
    application.dependency_overrides[get_session] = session_override
    async with application.router.lifespan_context(application):
        async with AsyncClient(
            transport=ASGITransport(app=application), base_url="http://test"
        ) as client:
            yield client


async def test_register_returns_only_public_user(
    registration_client: AsyncClient,
    db_session: AsyncSession,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caplog.set_level(logging.INFO)

    def forbidden_dns(*args: object, **kwargs: object) -> None:
        pytest.fail("L'inscription HTTP ne doit effectuer aucun lookup DNS email")

    monkeypatch.setattr(deliverability, "validate_email_deliverability", forbidden_dns)
    email = f"User-{uuid4()}+Tag@Example.COM"
    response = await registration_client.post(
        "/auth/register", json={"email": email, "password": PASSWORD}
    )
    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"id", "email", "is_active", "created_at"}
    assert body["email"] == email.casefold()
    assert body["is_active"] is True
    user = await db_session.get(User, UUID(body["id"]))
    assert user is not None
    assert verify_password(PASSWORD, user.password_hash)
    assert PASSWORD not in response.text
    assert user.password_hash not in response.text
    assert PASSWORD not in caplog.text
    assert user.password_hash not in caplog.text


@pytest.mark.parametrize("different_case", [False, True])
async def test_register_duplicate_is_generic_conflict(
    registration_client: AsyncClient, different_case: bool
) -> None:
    email = f"{uuid4()}@example.com"
    first = await registration_client.post(
        "/auth/register", json={"email": email, "password": PASSWORD}
    )
    assert first.status_code == 201
    duplicate = await registration_client.post(
        "/auth/register",
        json={
            "email": email.upper() if different_case else email,
            "password": PASSWORD,
        },
    )
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "Registration unavailable for this email."}
    assert first.json()["id"] not in duplicate.text
    assert PASSWORD not in duplicate.text


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("invalid-email", PASSWORD),
        (
            "a" * 64 + "@" + "b" * 63 + "." + "c" * 63 + "." + "d" * 58 + ".com",
            PASSWORD,
        ),
        ("valid@example.com", "x" * 14),
        ("valid@example.com", "x" * 129),
        ("valid@example.com", "x" * 14 + "\ud800"),
    ],
)
async def test_invalid_registration_is_private_and_does_not_persist(
    registration_client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    email: str,
    password: str,
) -> None:
    caplog.set_level(logging.INFO)

    def forbidden_hash(value: str) -> str:
        pytest.fail("Une requête invalide doit être refusée avant le hashing")

    monkeypatch.setattr(registration, "hash_password", forbidden_hash)
    before = await db_session.scalar(select(func.count()).select_from(User))
    # JSON échappé permet aussi de tester le rejet d'un surrogate isolé.
    response = await registration_client.post(
        "/auth/register",
        content=json.dumps({"email": email, "password": password}),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert all(
        set(error) == {"type", "loc", "msg"} for error in response.json()["detail"]
    )
    assert password not in response.text
    assert password not in caplog.text
    assert await db_session.scalar(select(func.count()).select_from(User)) == before


@pytest.mark.parametrize(
    "body",
    [
        {"password": PASSWORD},
        [{"password": PASSWORD}],
        {"email": "user@example.com", "password": {"secret": PASSWORD}},
    ],
)
async def test_validation_never_echoes_request_body(
    registration_client: AsyncClient, body: object
) -> None:
    response = await registration_client.post("/auth/register", json=body)
    assert response.status_code == 422
    assert PASSWORD not in response.text


async def test_malformed_json_does_not_echo_password(
    registration_client: AsyncClient,
) -> None:
    response = await registration_client.post(
        "/auth/register",
        content='{"password": "' + PASSWORD + '", invalid}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert PASSWORD not in response.text
