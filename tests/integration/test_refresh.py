import json
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from httpx2 import ASGITransport, AsyncClient
from sqlalchemy import delete, event, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.session import create_engine, get_session
from app.main import create_app
from app.models import RefreshToken, Session, User
from app.repositories.refresh_tokens import RefreshTokenRepository
from app.repositories.sessions import SessionRepository
from app.schemas.auth import LoginRequest, TokenPairResponse
from app.schemas.user import PublicUser
from app.security.refresh_tokens import hash_refresh_token
from app.security.tokens import decode_access_token
from app.services import refresh
from app.services.login import login_user
from tests.integration.test_login import PASSWORD, seed

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


@pytest.fixture
async def db() -> AsyncIterator[AsyncSession]:
    engine = create_engine(Settings())
    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session
    finally:
        await engine.dispose()


@pytest.fixture
def token_pairs() -> list[TokenPairResponse]:
    return []


@pytest.fixture
async def account(
    db: AsyncSession,
    caplog: pytest.LogCaptureFixture,
    token_pairs: list[TokenPairResponse],
) -> AsyncIterator[tuple[PublicUser, TokenPairResponse]]:
    caplog.set_level(logging.INFO)
    user = await seed(db)
    try:
        pair = await login_user(
            LoginRequest(email=user.email, password=PASSWORD), db, Settings()
        )
        token_pairs.append(pair)
        yield user, pair
        await db.rollback()
        async with db.begin():
            stored = await db.get(User, user.id)
            assert stored is not None
            digests = (
                await db.scalars(
                    select(RefreshToken.token_hash)
                    .join(Session)
                    .where(Session.user_id == user.id)
                )
            ).all()
            secrets = [PASSWORD, stored.password_hash]
            secrets.extend(
                value
                for issued_pair in token_pairs
                for value in (issued_pair.access_token, issued_pair.refresh_token)
            )
            secrets.extend(
                value for digest in digests for value in (digest.hex(), str(digest))
            )
        messages = "\n".join(
            record.getMessage()
            for phase in ("setup", "call", "teardown")
            for record in caplog.get_records(phase)
        )
        for secret in secrets:
            assert secret not in messages
    finally:
        await db.rollback()
        async with db.begin():
            await db.execute(delete(User).where(User.id == user.id))


@pytest.fixture
async def client(db: AsyncSession) -> AsyncIterator[AsyncClient]:
    async def override() -> AsyncIterator[AsyncSession]:
        try:
            yield db
        finally:
            # Comme la fermeture de la session par requête en production.
            await db.rollback()

    app = create_app()
    app.dependency_overrides[get_session] = override
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield client


def assert_not_stored(raw: str, row: RefreshToken) -> None:
    assert row.token_hash == hash_refresh_token(raw)
    assert len(row.token_hash) == 32
    for column in RefreshToken.__table__.columns:
        value = getattr(row, column.name)
        assert value != raw and value != raw.encode()


@pytest.mark.parametrize("age_days", [0, 20])
async def test_rotation_and_durable_replay(
    db: AsyncSession,
    account: tuple[PublicUser, TokenPairResponse],
    age_days: int,
    token_pairs: list[TokenPairResponse],
) -> None:
    user, first = account
    settings = Settings()
    claims1 = decode_access_token(first.access_token, settings)
    async with db.begin():
        original_session = await db.get(Session, claims1.session_id)
        assert original_session is not None
        if age_days:
            original_session.created_at -= timedelta(days=age_days)
            original_session.expires_at -= timedelta(days=age_days)
            initial = await RefreshTokenRepository(db).get_by_hash(
                hash_refresh_token(first.refresh_token)
            )
            assert initial is not None
            initial.issued_at = original_session.created_at
            initial.expires_at = original_session.expires_at
        expires = original_session.expires_at
    second = await refresh.refresh_tokens(first.refresh_token, db, settings)
    token_pairs.append(second)
    assert first.refresh_token != second.refresh_token
    claims2 = decode_access_token(second.access_token, settings)
    assert claims1.session_id == claims2.session_id
    assert claims1.user_id == claims2.user_id == user.id
    assert claims1.jti != claims2.jti
    async with db.begin():
        rows = (
            await db.scalars(
                select(RefreshToken).where(
                    RefreshToken.session_id == claims1.session_id
                )
            )
        ).all()
        assert len(rows) == 2
        previous = next(
            row
            for row in rows
            if row.token_hash == hash_refresh_token(first.refresh_token)
        )
        replacement = next(
            row
            for row in rows
            if row.token_hash == hash_refresh_token(second.refresh_token)
        )
        assert_not_stored(first.refresh_token, previous)
        assert_not_stored(second.refresh_token, replacement)
        assert previous.consumed_at == replacement.issued_at
        assert previous.replaced_by_id == replacement.id
        assert previous.session_id == replacement.session_id
        assert (
            replacement.consumed_at
            is replacement.revoked_at
            is replacement.replaced_by_id
            is None
        )
        assert previous.expires_at == replacement.expires_at == expires
        sessions = (
            await db.scalars(select(Session).where(Session.user_id == user.id))
        ).all()
        assert len(sessions) == 1 and sessions[0].expires_at == expires
    with pytest.raises(refresh.InvalidRefreshToken):
        await refresh.refresh_tokens(first.refresh_token, db, settings)
    assert db.in_transaction() is False
    # Une autre connexion observe le commit réel, sans savepoint externe.
    engine = create_engine(settings)
    try:
        async with AsyncSession(engine) as reader:
            server_session = await reader.get(Session, claims1.session_id)
            assert server_session is not None and server_session.revoked_at is not None
            assert server_session.revocation_reason == "refresh_token_reuse"
            family = (
                await reader.scalars(
                    select(RefreshToken).where(
                        RefreshToken.session_id == claims1.session_id
                    )
                )
            ).all()
            assert len(family) == 2 and all(
                row.revoked_at is not None for row in family
            )
    finally:
        await engine.dispose()


async def test_replay_invalidates_descendant_and_access(
    db: AsyncSession,
    client: AsyncClient,
    account: tuple[PublicUser, TokenPairResponse],
    caplog: pytest.LogCaptureFixture,
    token_pairs: list[TokenPairResponse],
) -> None:
    caplog.set_level(logging.INFO)
    _, first = account
    result = await client.post(
        "/auth/refresh", json={"refresh_token": first.refresh_token}
    )
    assert result.status_code == 200
    body = result.json()
    token_pairs.append(TokenPairResponse.model_validate(body))
    assert set(body) == {"access_token", "refresh_token", "token_type", "expires_in"}
    assert body["token_type"] == "bearer" and body["expires_in"] == 900
    assert (
        await client.get(
            "/users/me", headers={"Authorization": f"Bearer {body['access_token']}"}
        )
    ).status_code == 200
    for raw in (first.refresh_token, body["refresh_token"]):
        result = await client.post("/auth/refresh", json={"refresh_token": raw})
        assert result.status_code == 401
        assert result.json() == {"detail": "Invalid refresh token."}
        assert raw not in result.text
    for access in (first.access_token, body["access_token"]):
        assert (
            await client.get("/users/me", headers={"Authorization": f"Bearer {access}"})
        ).status_code == 401
    for secret in (
        first.access_token,
        first.refresh_token,
        body["access_token"],
        body["refresh_token"],
        PASSWORD,
    ):
        assert secret not in caplog.text
    # Le logout d'une famille déjà révoquée ne remplace pas le motif du replay.
    assert (
        await client.post("/auth/logout", json={"refresh_token": first.refresh_token})
    ).status_code == 204
    async with db.begin():
        sid = decode_access_token(first.access_token, Settings()).session_id
        server_session = await db.get(Session, sid)
        assert server_session is not None
        assert server_session.revocation_reason == "refresh_token_reuse"


@pytest.mark.parametrize(
    "case",
    [
        "token_expired",
        "session_expired",
        "token_revoked",
        "session_revoked",
        "inactive",
    ],
)
async def test_refresh_rejected_state(
    db: AsyncSession,
    client: AsyncClient,
    account: tuple[PublicUser, TokenPairResponse],
    case: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    user, pair = account
    sid = decode_access_token(pair.access_token, Settings()).session_id
    now = datetime.now(UTC)
    async with db.begin():
        if case == "token_expired":
            await db.execute(
                update(RefreshToken)
                .where(RefreshToken.session_id == sid)
                .values(
                    issued_at=now - timedelta(days=2),
                    expires_at=now - timedelta(days=1),
                )
            )
        elif case == "session_expired":
            await db.execute(
                update(Session)
                .where(Session.id == sid)
                .values(
                    created_at=now - timedelta(days=2),
                    expires_at=now - timedelta(days=1),
                )
            )
        elif case == "token_revoked":
            await db.execute(
                update(RefreshToken)
                .where(RefreshToken.session_id == sid)
                .values(revoked_at=now)
            )
        elif case == "session_revoked":
            await db.execute(
                update(Session)
                .where(Session.id == sid)
                .values(revoked_at=now, revocation_reason="existing_reason")
            )
        else:
            await db.execute(
                update(User).where(User.id == user.id).values(is_active=False)
            )
        stored_user = await db.get(User, user.id)
        assert stored_user is not None
        password_hash = stored_user.password_hash
    result = await client.post(
        "/auth/refresh", json={"refresh_token": pair.refresh_token}
    )
    assert result.status_code == 401 and result.json() == {
        "detail": "Invalid refresh token."
    }
    for secret in (
        pair.refresh_token,
        pair.access_token,
        hash_refresh_token(pair.refresh_token).hex(),
        str(hash_refresh_token(pair.refresh_token)),
        PASSWORD,
        password_hash,
    ):
        assert secret not in result.text and secret not in caplog.text
    db.expunge_all()
    async with db.begin():
        rows = (
            await db.scalars(select(RefreshToken).where(RefreshToken.session_id == sid))
        ).all()
        assert (
            len(rows) == 1
            and rows[0].consumed_at is None
            and rows[0].replaced_by_id is None
        )
        session = await db.get(Session, sid)
        assert session is not None
        if case == "inactive":
            assert (
                session.revoked_at is not None
                and session.revocation_reason == "user_inactive"
            )
            assert rows[0].revoked_at is not None
            await db.execute(
                update(User).where(User.id == user.id).values(is_active=True)
            )
        elif case == "session_revoked":
            assert session.revocation_reason == "existing_reason"
    if case == "inactive":
        assert (
            await client.post(
                "/auth/refresh", json={"refresh_token": pair.refresh_token}
            )
        ).status_code == 401
        assert (
            await client.get(
                "/users/me", headers={"Authorization": f"Bearer {pair.access_token}"}
            )
        ).status_code == 401


@pytest.mark.parametrize("raw", ["f" * 64, "arbitrary", "", " ABC ", "\ud800"])
async def test_unknown_refresh_and_logout(client: AsyncClient, raw: str) -> None:
    content = json.dumps({"refresh_token": raw})
    result = await client.post(
        "/auth/refresh", content=content, headers={"Content-Type": "application/json"}
    )
    assert result.status_code == 401 and result.json() == {
        "detail": "Invalid refresh token."
    }
    logout = await client.post(
        "/auth/logout", content=content, headers={"Content-Type": "application/json"}
    )
    assert logout.status_code == 204 and logout.content == b""


@pytest.mark.parametrize("endpoint", ["refresh", "logout"])
@pytest.mark.parametrize(
    "body", [{}, {"refresh_token": "SENTINEL" * 40}, {"refresh_token": 123}]
)
async def test_refresh_validation_private(
    client: AsyncClient,
    endpoint: str,
    body: dict[str, object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    result = await client.post(f"/auth/{endpoint}", json=body)
    assert result.status_code == 422
    error = result.json()["detail"][0]
    assert error["msg"] == "Invalid refresh token."
    assert set(error) == {"type", "loc", "msg"}
    assert "SENTINEL" not in result.text and "SENTINEL" not in caplog.text


@pytest.mark.parametrize("rotate_first", [False, True])
async def test_logout_idempotent_and_old_token(
    db: AsyncSession,
    client: AsyncClient,
    account: tuple[PublicUser, TokenPairResponse],
    rotate_first: bool,
    caplog: pytest.LogCaptureFixture,
    token_pairs: list[TokenPairResponse],
) -> None:
    caplog.set_level(logging.INFO)
    _, first = account
    current = (
        await refresh.refresh_tokens(first.refresh_token, db, Settings())
        if rotate_first
        else first
    )
    if rotate_first:
        token_pairs.append(current)
    sid = decode_access_token(first.access_token, Settings()).session_id
    original_revoked = None
    for _ in range(2):
        # Aucun access token n'est fourni au logout.
        result = await client.post(
            "/auth/logout", json={"refresh_token": first.refresh_token}
        )
        assert result.status_code == 204 and result.content == b""
        db.expunge_all()
        async with db.begin():
            server_session = await db.get(Session, sid)
            assert server_session is not None and server_session.revoked_at is not None
            assert server_session.revocation_reason == "logout"
            if original_revoked is not None:
                assert server_session.revoked_at == original_revoked
            original_revoked = server_session.revoked_at
            rows = (
                await db.scalars(
                    select(RefreshToken).where(RefreshToken.session_id == sid)
                )
            ).all()
            assert len(rows) == (2 if rotate_first else 1)
            assert all(row.revoked_at is not None for row in rows)
    for access in (first.access_token, current.access_token):
        assert (
            await client.get("/users/me", headers={"Authorization": f"Bearer {access}"})
        ).status_code == 401
    assert (
        await client.post(
            "/auth/refresh", json={"refresh_token": current.refresh_token}
        )
    ).status_code == 401
    for secret in (
        first.access_token,
        first.refresh_token,
        current.access_token,
        current.refresh_token,
        PASSWORD,
    ):
        assert secret not in caplog.text


@pytest.mark.parametrize("failure", ["signing", "flush", "before_commit"])
async def test_rotation_error_rolls_back(
    db: AsyncSession,
    account: tuple[PublicUser, TokenPairResponse],
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    _, pair = account

    def fail(*args: object) -> str:
        raise RuntimeError("controlled transaction failure")

    if failure == "signing":
        monkeypatch.setattr(refresh, "create_access_token", fail)
    else:
        event.listen(
            db.sync_session,
            "before_flush" if failure == "flush" else "before_commit",
            fail,
        )
    try:
        with pytest.raises(RuntimeError, match="controlled transaction failure"):
            await refresh.refresh_tokens(pair.refresh_token, db, Settings())
    finally:
        if failure != "signing":
            event.remove(
                db.sync_session,
                "before_flush" if failure == "flush" else "before_commit",
                fail,
            )
    assert db.in_transaction() is False
    async with db.begin():
        sid = decode_access_token(pair.access_token, Settings()).session_id
        rows = (
            await db.scalars(select(RefreshToken).where(RefreshToken.session_id == sid))
        ).all()
        assert (
            len(rows) == 1
            and rows[0].consumed_at is None
            and rows[0].replaced_by_id is None
        )


async def test_replay_reloads_cached_token(
    db: AsyncSession,
    account: tuple[PublicUser, TokenPairResponse],
    token_pairs: list[TokenPairResponse],
) -> None:
    pair = account[1]
    async with db.begin():
        cached = await RefreshTokenRepository(db).get_by_hash(
            hash_refresh_token(pair.refresh_token)
        )
        assert cached is not None and cached.consumed_at is None
    engine = create_engine(Settings())
    try:
        async with AsyncSession(engine, expire_on_commit=False) as other:
            replacement = await refresh.refresh_tokens(
                pair.refresh_token, other, Settings()
            )
            token_pairs.append(replacement)
        assert cached.consumed_at is None
        with pytest.raises(refresh.InvalidRefreshToken):
            await refresh.refresh_tokens(pair.refresh_token, db, Settings())
        assert cached.consumed_at is not None
        async with db.begin():
            server_session = await db.get(Session, cached.session_id)
            assert server_session is not None
            assert server_session.revocation_reason == "refresh_token_reuse"
    finally:
        await engine.dispose()


async def test_logout_accepts_expired_refresh(
    db: AsyncSession, client: AsyncClient, account: tuple[PublicUser, TokenPairResponse]
) -> None:
    pair = account[1]
    now = datetime.now(UTC)
    sid = decode_access_token(pair.access_token, Settings()).session_id
    async with db.begin():
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.session_id == sid)
            .values(
                issued_at=now - timedelta(days=2), expires_at=now - timedelta(days=1)
            )
        )
    result = await client.post(
        "/auth/logout", json={"refresh_token": pair.refresh_token}
    )
    assert result.status_code == 204 and result.content == b""
    async with db.begin():
        server_session = await db.get(Session, sid)
        assert (
            server_session is not None and server_session.revocation_reason == "logout"
        )


@pytest.mark.parametrize("failure", ["flush", "before_commit"])
async def test_login_transaction_error_creates_no_family(
    db: AsyncSession, account: tuple[PublicUser, TokenPairResponse], failure: str
) -> None:
    user, first = account
    commits = 0

    def fail(*args: object) -> None:
        nonlocal commits
        if failure == "before_commit":
            commits += 1
            if commits == 1:  # Laisser terminer le lookup avant Argon2.
                return
        raise RuntimeError("controlled login transaction failure")

    hook = "before_flush" if failure == "flush" else "before_commit"
    event.listen(db.sync_session, hook, fail)
    try:
        with pytest.raises(RuntimeError, match="controlled login transaction failure"):
            await login_user(
                LoginRequest(email=user.email, password=PASSWORD), db, Settings()
            )
    finally:
        event.remove(db.sync_session, hook, fail)
    assert db.in_transaction() is False
    async with db.begin():
        sessions = (
            await db.scalars(select(Session).where(Session.user_id == user.id))
        ).all()
        tokens = (
            await db.scalars(
                select(RefreshToken).join(Session).where(Session.user_id == user.id)
            )
        ).all()
        assert len(sessions) == len(tokens) == 1
        assert tokens[0].token_hash == hash_refresh_token(first.refresh_token)


@pytest.mark.parametrize("operation", ["refresh", "logout"])
async def test_session_lock_precedes_token_mutation(
    db: AsyncSession,
    client: AsyncClient,
    account: tuple[PublicUser, TokenPairResponse],
    operation: str,
    token_pairs: list[TokenPairResponse],
) -> None:
    statements: list[str] = []

    def capture(
        conn: object,
        cursor: object,
        statement: str,
        parameters: object,
        context: object,
        executemany: bool,
    ) -> None:
        statements.append(statement.lower())

    engine = db.bind
    assert engine is not None
    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        result = await client.post(
            f"/auth/{operation}", json={"refresh_token": account[1].refresh_token}
        )
        assert result.status_code == (200 if operation == "refresh" else 204)
        if operation == "refresh":
            token_pairs.append(TokenPairResponse.model_validate(result.json()))
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)
    session_lock = next(
        i
        for i, sql in enumerate(statements)
        if "from sessions" in sql and "for update" in sql
    )
    token_lock = next(
        i
        for i, sql in enumerate(statements)
        if ("from refresh_tokens" in sql and "for update" in sql)
        or sql.startswith("update refresh_tokens")
    )
    assert session_lock < token_lock
    assert (
        "refresh_tokens.session_id" in statements[0]
        and "for update" not in statements[0]
    )
    assert "refresh_tokens.token_hash" not in statements[0].split("from")[0]


@pytest.mark.parametrize("target", ["session", "token"])
async def test_repository_for_update_holds_real_postgres_lock(
    db: AsyncSession, account: tuple[PublicUser, TokenPairResponse], target: str
) -> None:
    pair = account[1]
    sid = decode_access_token(pair.access_token, Settings()).session_id
    engine = create_engine(Settings())
    try:
        async with db.begin():
            await SessionRepository(db).get_by_id_for_update(sid)
            if target == "token":
                await RefreshTokenRepository(db).get_by_hash_for_update(
                    hash_refresh_token(pair.refresh_token)
                )
            async with AsyncSession(engine) as contender:
                with pytest.raises(DBAPIError) as error:
                    async with contender.begin():
                        await contender.execute(
                            text("SET LOCAL lock_timeout = '100ms'")
                        )
                        if target == "session":
                            await SessionRepository(contender).get_by_id_for_update(sid)
                        else:
                            # Sonde de verrou uniquement, aucune mutation de famille.
                            await RefreshTokenRepository(
                                contender
                            ).get_by_hash_for_update(
                                hash_refresh_token(pair.refresh_token)
                            )
                assert error.value.orig.sqlstate == "55P03"
    finally:
        await engine.dispose()
