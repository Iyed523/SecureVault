import json
import logging
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from email_validator import deliverability
from httpx2 import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.session import get_session
from app.main import create_app
from app.models import RefreshToken, Session, User
from app.schemas.auth import LoginRequest, RegistrationRequest
from app.schemas.user import PublicUser
from app.security.tokens import create_access_token, decode_access_token
from app.services import login
from app.services.registration import register_user

pytestmark = [pytest.mark.integration, pytest.mark.anyio]
PASSWORD = "  Une phrase fictive login 🔐  "


async def seed(db: AsyncSession) -> PublicUser:
    return await register_user(
        RegistrationRequest(email=f"{uuid4()}@example.com", password=PASSWORD), db
    )


@pytest.fixture
async def client(db_session: AsyncSession) -> AsyncIterator[AsyncClient]:
    async def override() -> AsyncIterator[AsyncSession]:
        yield db_session

    app = create_app()
    app.dependency_overrides[get_session] = override
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as http:
            yield http


@pytest.mark.parametrize("expire_on_commit", [False, True])
async def test_login_success(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    expire_on_commit: bool,
) -> None:
    user = await seed(db_session)
    db_session.sync_session.expire_on_commit = expire_on_commit
    calls = []
    real_verify = login.verify_password

    def spy(password: str, encoded: str) -> bool:
        assert db_session.in_transaction() is False
        calls.append(encoded)
        return real_verify(password, encoded)

    monkeypatch.setattr(login, "verify_password", spy)
    settings = Settings()
    result = await login.login_user(
        LoginRequest(email=user.email.upper(), password=PASSWORD), db_session, settings
    )
    assert not db_session.in_transaction()
    assert len(calls) == 1
    assert result.token_type == "bearer" and result.expires_in == 900
    claims = decode_access_token(result.access_token, settings)
    assert claims.user_id == user.id
    rows = (
        await db_session.scalars(select(Session).where(Session.user_id == user.id))
    ).all()
    assert len(rows) == 1
    session = rows[0]
    assert session.id == claims.session_id and session.id.version == 4
    assert session.created_at.utcoffset() == timedelta(0)
    assert session.expires_at - session.created_at == timedelta(days=30)
    assert (
        session.revoked_at is session.last_used_at is session.revocation_reason is None
    )
    assert (
        await db_session.scalar(
            select(RefreshToken.id).where(RefreshToken.session_id == session.id)
        )
        is None
    )


@pytest.mark.parametrize("case", ["missing", "wrong", "inactive"])
async def test_failures_verify_argon2_and_create_no_session(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    user = await seed(db_session)
    if case == "inactive":
        await db_session.execute(
            update(User).where(User.id == user.id).values(is_active=False)
        )
        await db_session.commit()
    calls = []
    real_verify = login.verify_password

    def spy(password: str, encoded: str) -> bool:
        assert db_session.in_transaction() is False
        calls.append(encoded)
        return real_verify(password, encoded)

    monkeypatch.setattr(login, "verify_password", spy)
    email = f"{uuid4()}@example.com" if case == "missing" else user.email
    request = LoginRequest(
        email=email, password="wrong" if case == "wrong" else PASSWORD
    )
    with pytest.raises(login.InvalidCredentials):
        await login.login_user(request, db_session, Settings())
    assert len(calls) == 1
    assert (calls[0] == login.DUMMY_PASSWORD_HASH) is (case == "missing")
    assert not db_session.in_transaction()
    assert (
        await db_session.scalar(select(Session.id).where(Session.user_id == user.id))
        is None
    )


@pytest.mark.parametrize("case", ["inactive", "password_changed", "deleted"])
async def test_login_revalidates_user_after_password_verification(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    user = await seed(db_session)
    real_threadpool = login.run_in_threadpool
    calls = []

    async def change_after_verification(
        verify: Callable[[str, str], bool], password: str, encoded: str
    ) -> bool:
        assert db_session.in_transaction() is False
        valid = await real_threadpool(verify, password, encoded)
        assert valid is True
        calls.append(encoded)
        if case == "deleted":
            statement = delete(User).where(User.id == user.id)
        else:
            statement = (
                update(User)
                .where(User.id == user.id)
                .values(
                    {"is_active": False}
                    if case == "inactive"
                    else {"password_hash": login.DUMMY_PASSWORD_HASH}
                )
            )
        # SQL réel sans synchroniser le cache ORM : la relecture doit le rafraîchir.
        async with db_session.begin():
            await db_session.execute(
                statement.execution_options(synchronize_session=False)
            )
        return valid

    monkeypatch.setattr(login, "run_in_threadpool", change_after_verification)
    with pytest.raises(login.InvalidCredentials):
        await login.login_user(
            LoginRequest(email=user.email, password=PASSWORD), db_session, Settings()
        )
    assert len(calls) == 1
    assert db_session.in_transaction() is False
    assert (
        await db_session.scalar(select(Session.id).where(Session.user_id == user.id))
        is None
    )


async def test_signing_failure_rolls_back_session(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await seed(db_session)
    flushed_ids = []

    def fail(user_id: object, session_id: object, settings: Settings) -> str:
        flushed_ids.append(session_id)
        raise RuntimeError("controlled signing failure")

    monkeypatch.setattr(login, "create_access_token", fail)
    with pytest.raises(RuntimeError, match="controlled signing failure"):
        await login.login_user(
            LoginRequest(email=user.email, password=PASSWORD), db_session, Settings()
        )
    assert len(flushed_ids) == 1
    assert not db_session.in_transaction()
    assert (
        await db_session.scalar(select(Session.id).where(Session.user_id == user.id))
        is None
    )


@pytest.mark.parametrize("bearer_spaces", [" ", "    "])
async def test_login_and_me_http(
    client: AsyncClient,
    db_session: AsyncSession,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    bearer_spaces: str,
) -> None:
    caplog.set_level(logging.INFO)
    user = await seed(db_session)

    def no_dns(*args: object, **kwargs: object) -> None:
        pytest.fail("DNS lookup")

    monkeypatch.setattr(deliverability, "validate_email_deliverability", no_dns)
    result = await client.post(
        "/auth/login", json={"email": user.email.upper(), "password": PASSWORD}
    )
    assert result.status_code == 200
    body = result.json()
    assert set(body) == {"access_token", "token_type", "expires_in"}
    assert body["token_type"] == "bearer" and body["expires_in"] == 900
    me = await client.get(
        "/users/me",
        headers={"Authorization": f"Bearer{bearer_spaces}{body['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json() == user.model_dump(mode="json")
    stored = await db_session.get(User, user.id)
    assert stored is not None
    for response in (result, me):
        assert PASSWORD not in response.text
        assert stored.password_hash not in response.text
    assert PASSWORD not in caplog.text and stored.password_hash not in caplog.text
    assert body["access_token"] not in caplog.text
    server_session = await db_session.scalar(
        select(Session).where(Session.user_id == user.id)
    )
    assert server_session is not None and server_session.last_used_at is None


@pytest.mark.parametrize("case", ["missing", "wrong", "inactive", "empty"])
async def test_login_http_failure(
    client: AsyncClient,
    db_session: AsyncSession,
    case: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    user = await seed(db_session)
    if case == "inactive":
        await db_session.execute(
            update(User).where(User.id == user.id).values(is_active=False)
        )
        await db_session.commit()
    email = f"{uuid4()}@example.com" if case == "missing" else user.email
    password = "" if case == "empty" else "wrong" if case == "wrong" else PASSWORD
    result = await client.post(
        "/auth/login", json={"email": email, "password": password}
    )
    assert result.status_code == 401
    assert result.json() == {"detail": "Invalid credentials."}
    assert result.headers["www-authenticate"] == "Bearer"
    assert PASSWORD not in result.text and PASSWORD not in caplog.text
    if case == "wrong":
        assert password == "wrong"
        assert password not in result.text and password not in caplog.text
    stored = await db_session.get(User, user.id)
    assert stored is not None
    assert stored.password_hash not in result.text
    assert stored.password_hash not in caplog.text
    assert (
        await db_session.scalar(select(Session.id).where(Session.user_id == user.id))
        is None
    )


@pytest.mark.parametrize(
    "header", [None, "Basic abc", "Bearer", "Bearer ", "Bearer invalid"]
)
async def test_missing_or_malformed_bearer(
    client: AsyncClient, header: str | None
) -> None:
    result = await client.get(
        "/users/me", headers={} if header is None else {"Authorization": header}
    )
    assert result.status_code == 401
    assert result.json() == {"detail": "Invalid credentials."}
    assert result.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "case",
    [
        "signature",
        "expired",
        "issuer",
        "audience",
        "type",
        "missing_session",
        "revoked",
        "expired_session",
        "other_user",
        "disabled",
        "deleted_user",
    ],
)
async def test_me_rejects_invalid_token_or_database_state(
    client: AsyncClient, db_session: AsyncSession, case: str
) -> None:
    user = await seed(db_session)
    settings = Settings()
    result = await login.login_user(
        LoginRequest(email=user.email, password=PASSWORD), db_session, settings
    )
    token = result.access_token
    claims = decode_access_token(token, settings)
    data = jwt.decode(
        token,
        settings.jwt_signing_key(),
        algorithms=["HS256"],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )
    if case in ("signature", "expired", "issuer", "audience", "type"):
        changes = {
            "expired": ("exp", 1),
            "issuer": ("iss", "other"),
            "audience": ("aud", "other"),
            "type": ("type", "refresh"),
        }
        if case != "signature":
            key, value = changes[case]
            data[key] = value
        token = jwt.encode(
            data,
            b"x" * 32 if case == "signature" else settings.jwt_signing_key(),
            algorithm="HS256",
        )
    elif case == "other_user":
        other = await seed(db_session)
        token = create_access_token(other.id, claims.session_id, settings)
    else:
        now = datetime.now(UTC)
        if case == "missing_session":
            await db_session.execute(
                delete(Session).where(Session.id == claims.session_id)
            )
        elif case == "revoked":
            await db_session.execute(
                update(Session)
                .where(Session.id == claims.session_id)
                .values(revoked_at=now)
            )
        elif case == "expired_session":
            await db_session.execute(
                update(Session)
                .where(Session.id == claims.session_id)
                .values(
                    created_at=now - timedelta(days=31),
                    expires_at=now - timedelta(seconds=1),
                )
            )
        elif case == "disabled":
            await db_session.execute(
                update(User).where(User.id == user.id).values(is_active=False)
            )
        elif case == "deleted_user":
            await db_session.execute(delete(User).where(User.id == user.id))
        await db_session.commit()
        db_session.expunge_all()
    response = await client.get(
        "/users/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials."}
    assert response.headers["www-authenticate"] == "Bearer"
    assert token not in response.text


async def test_login_validation_is_private(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    before = await db_session.scalar(select(func.count()).select_from(Session))
    for password in ("x" * 129,):
        response = await client.post(
            "/auth/login", json={"email": "user@example.com", "password": password}
        )
        assert response.status_code == 422
        assert password not in json.dumps(response.json(), ensure_ascii=False)
        assert response.json()["detail"][0]["msg"] == "Invalid password."
    assert await db_session.scalar(select(func.count()).select_from(Session)) == before


async def test_login_invalid_unicode_is_generic_401(client: AsyncClient) -> None:
    secret = "x" * 14 + "\ud800"
    response = await client.post(
        "/auth/login",
        content=json.dumps({"email": f"{uuid4()}@example.com", "password": secret}),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials."}
    assert response.headers["www-authenticate"] == "Bearer"
