from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.base import Base
from app.models import RefreshToken, Session, User
from tests.integration.helpers import make_token_hash

pytestmark = [pytest.mark.integration, pytest.mark.anyio]
ISSUED = datetime(2026, 1, 1, tzinfo=UTC)
EXPIRES = ISSUED + timedelta(days=1)


async def make_user(db: AsyncSession) -> User:
    user = User(
        email=f"{uuid4()}@example.invalid", password_hash="FAKE-PHC-NOT-A-PASSWORD"
    )
    db.add(user)
    await db.flush()
    return user


async def make_session(db: AsyncSession) -> Session:
    user = await make_user(db)
    session = Session(user_id=user.id, created_at=ISSUED, expires_at=EXPIRES)
    db.add(session)
    await db.flush()
    return session


async def make_token(db: AsyncSession) -> RefreshToken:
    session = await make_session(db)
    token = RefreshToken(
        session_id=session.id,
        token_hash=make_token_hash(),
        issued_at=ISSUED,
        expires_at=EXPIRES,
    )
    db.add(token)
    await db.flush()
    return token


async def assert_rejected(db: AsyncSession, model: Base, constraint: str) -> None:
    with pytest.raises(IntegrityError) as caught:
        async with db.begin_nested():
            db.add(model)
            await db.flush()
    assert constraint in str(caught.value.orig)


async def test_user_defaults_and_update(db_session: AsyncSession) -> None:
    user = await make_user(db_session)
    await db_session.refresh(user)
    assert isinstance(user.id, UUID) and user.id.version == 4
    assert user.is_active is True
    assert user.created_at.utcoffset() == timedelta(0)
    assert user.updated_at.utcoffset() == timedelta(0)
    user.updated_at = ISSUED
    await db_session.flush()
    user.is_active = False
    await db_session.flush()
    await db_session.refresh(user)
    assert user.updated_at > ISSUED


async def test_user_email_unique(db_session: AsyncSession) -> None:
    user = await make_user(db_session)
    await assert_rejected(
        db_session,
        User(email=user.email, password_hash="FAKE-PHC"),
        "uq_users_email",
    )


async def test_user_password_hash_required(db_session: AsyncSession) -> None:
    await assert_rejected(
        db_session, User(email="missing-hash@example.invalid"), "password_hash"
    )


async def test_session_persistence(db_session: AsyncSession) -> None:
    session = await make_session(db_session)
    await db_session.refresh(session)
    assert session.id.version == 4
    assert await db_session.get(User, session.user_id) is not None
    assert session.created_at == ISSUED
    assert session.expires_at == EXPIRES
    assert session.created_at.utcoffset() == timedelta(0)
    assert session.last_used_at is None
    assert session.revoked_at is None
    assert session.revocation_reason is None


@pytest.mark.parametrize(
    ("field", "value", "constraint"),
    [
        ("expires_at", ISSUED, "ck_sessions_expires_after_creation"),
        (
            "expires_at",
            ISSUED - timedelta(seconds=1),
            "ck_sessions_expires_after_creation",
        ),
        (
            "last_used_at",
            ISSUED - timedelta(seconds=1),
            "ck_sessions_last_used_after_creation",
        ),
        (
            "revoked_at",
            ISSUED - timedelta(seconds=1),
            "ck_sessions_revoked_after_creation",
        ),
    ],
)
async def test_session_temporal_constraints(
    db_session: AsyncSession, field: str, value: datetime, constraint: str
) -> None:
    user = await make_user(db_session)
    session = Session(user_id=user.id, created_at=ISSUED, expires_at=EXPIRES)
    setattr(session, field, value)
    await assert_rejected(db_session, session, constraint)


async def test_session_requires_existing_user(db_session: AsyncSession) -> None:
    await assert_rejected(
        db_session,
        Session(user_id=uuid4(), created_at=ISSUED, expires_at=EXPIRES),
        "fk_sessions_user_id_users",
    )


async def test_token_persistence(db_session: AsyncSession) -> None:
    token = await make_token(db_session)
    expected_hash = token.token_hash
    await db_session.refresh(token)
    assert token.id.version == 4
    assert isinstance(token.token_hash, bytes) and len(token.token_hash) == 32
    assert token.token_hash == expected_hash
    assert token.issued_at.utcoffset() == timedelta(0)
    assert token.expires_at == EXPIRES
    assert token.consumed_at is None
    assert token.revoked_at is None
    assert token.replaced_by_id is None


async def test_token_hash_unique(db_session: AsyncSession) -> None:
    token = await make_token(db_session)
    await assert_rejected(
        db_session,
        RefreshToken(
            session_id=token.session_id,
            token_hash=token.token_hash,
            expires_at=EXPIRES,
            issued_at=ISSUED,
        ),
        "uq_refresh_tokens_token_hash",
    )


@pytest.mark.parametrize("size", [0, 31, 33])
async def test_token_hash_length(db_session: AsyncSession, size: int) -> None:
    session = await make_session(db_session)
    await assert_rejected(
        db_session,
        RefreshToken(
            session_id=session.id,
            token_hash=b"x" * size,
            issued_at=ISSUED,
            expires_at=EXPIRES,
        ),
        "ck_refresh_tokens_hash_length",
    )


@pytest.mark.parametrize(
    ("field", "value", "constraint"),
    [
        ("expires_at", ISSUED, "ck_refresh_tokens_expires_after_issue"),
        (
            "expires_at",
            ISSUED - timedelta(seconds=1),
            "ck_refresh_tokens_expires_after_issue",
        ),
        (
            "consumed_at",
            ISSUED - timedelta(seconds=1),
            "ck_refresh_tokens_consumed_after_issue",
        ),
        (
            "revoked_at",
            ISSUED - timedelta(seconds=1),
            "ck_refresh_tokens_revoked_after_issue",
        ),
    ],
)
async def test_token_temporal_constraints(
    db_session: AsyncSession, field: str, value: datetime, constraint: str
) -> None:
    session = await make_session(db_session)
    token = RefreshToken(
        session_id=session.id,
        token_hash=make_token_hash(),
        issued_at=ISSUED,
        expires_at=EXPIRES,
    )
    setattr(token, field, value)
    await assert_rejected(db_session, token, constraint)


async def test_token_requires_existing_session(db_session: AsyncSession) -> None:
    await assert_rejected(
        db_session,
        RefreshToken(
            session_id=uuid4(),
            token_hash=make_token_hash(),
            issued_at=ISSUED,
            expires_at=EXPIRES,
        ),
        "fk_refresh_tokens_session_id_sessions",
    )


async def test_replacement_unique_and_set_null(db_session: AsyncSession) -> None:
    old = await make_token(db_session)
    successor = RefreshToken(
        session_id=old.session_id,
        token_hash=make_token_hash(),
        issued_at=ISSUED,
        expires_at=EXPIRES,
    )
    db_session.add(successor)
    await db_session.flush()
    old.replaced_by_id = successor.id
    await db_session.flush()
    await assert_rejected(
        db_session,
        RefreshToken(
            session_id=old.session_id,
            token_hash=make_token_hash(),
            issued_at=ISSUED,
            expires_at=EXPIRES,
            replaced_by_id=successor.id,
        ),
        "uq_refresh_tokens_replaced_by_id",
    )
    await db_session.execute(
        delete(RefreshToken).where(RefreshToken.id == successor.id)
    )
    await db_session.refresh(old)
    assert old.replaced_by_id is None


async def test_replacement_requires_existing_token(db_session: AsyncSession) -> None:
    session = await make_session(db_session)
    await assert_rejected(
        db_session,
        RefreshToken(
            session_id=session.id,
            token_hash=make_token_hash(),
            issued_at=ISSUED,
            expires_at=EXPIRES,
            replaced_by_id=uuid4(),
        ),
        "fk_refresh_tokens_replaced_by_id_refresh_tokens",
    )


async def test_token_cannot_replace_itself(db_session: AsyncSession) -> None:
    session = await make_session(db_session)
    token_id = uuid4()
    await assert_rejected(
        db_session,
        RefreshToken(
            id=token_id,
            session_id=session.id,
            token_hash=make_token_hash(),
            issued_at=ISSUED,
            expires_at=EXPIRES,
            replaced_by_id=token_id,
        ),
        "ck_refresh_tokens_replacement_not_self",
    )


@pytest.mark.parametrize("parent", [User, Session])
async def test_database_delete_cascades(
    db_session: AsyncSession, parent: type[User] | type[Session]
) -> None:
    token = await make_token(db_session)
    session = await db_session.get(Session, token.session_id)
    assert session is not None
    parent_id = session.user_id if parent is User else session.id
    await db_session.execute(delete(parent).where(parent.id == parent_id))
    assert (
        await db_session.scalar(
            select(RefreshToken.id).where(RefreshToken.id == token.id)
        )
        is None
    )
    assert (
        await db_session.scalar(select(Session.id).where(Session.id == session.id))
        is None
    )


@pytest.mark.parametrize("loaded", [False, True])
@pytest.mark.parametrize("parent", [User, Session])
async def test_orm_delete_cascades(
    db_session: AsyncSession, loaded: bool, parent: type[User] | type[Session]
) -> None:
    token = await make_token(db_session)
    session = await db_session.get(Session, token.session_id)
    assert session is not None
    if parent is User:
        query = select(User).where(User.id == session.user_id)
        if loaded:
            query = query.options(
                selectinload(User.sessions).selectinload(Session.refresh_tokens)
            )
        target = (await db_session.execute(query)).scalar_one()
    else:
        session_query = select(Session).where(Session.id == session.id)
        if loaded:
            session_query = session_query.options(selectinload(Session.refresh_tokens))
        target = (await db_session.execute(session_query)).scalar_one()
    await db_session.delete(target)
    await db_session.flush()
    assert (
        await db_session.scalar(
            select(RefreshToken.id).where(RefreshToken.id == token.id)
        )
        is None
    )
    assert (
        await db_session.scalar(select(Session.id).where(Session.id == session.id))
        is None
    )


@pytest.mark.parametrize("parent", [User, Session])
async def test_disassociation_does_not_delete_child(
    db_session: AsyncSession, parent: type[User] | type[Session]
) -> None:
    token = await make_token(db_session)
    session = await db_session.get(Session, token.session_id)
    assert session is not None
    token_id, session_id, user_id = token.id, session.id, session.user_id
    user = (
        await db_session.execute(
            select(User)
            .where(User.id == user_id)
            .options(selectinload(User.sessions).selectinload(Session.refresh_tokens))
        )
    ).scalar_one()

    with pytest.raises(IntegrityError) as caught:
        async with db_session.begin_nested():
            if parent is User:
                user.sessions.remove(session)
            else:
                session.refresh_tokens.remove(token)
            await db_session.flush()

    assert caught.value.orig.sqlstate == "23502"  # PostgreSQL NOT NULL violation
    column = "user_id" if parent is User else "session_id"
    assert column in str(caught.value.orig)
    assert (
        await db_session.scalar(select(Session.user_id).where(Session.id == session_id))
        == user_id
    )
    assert (
        await db_session.scalar(
            select(RefreshToken.session_id).where(RefreshToken.id == token_id)
        )
        == session_id
    )


async def test_database_column_types(db_session: AsyncSession) -> None:
    result = await db_session.execute(
        text(
            "SELECT table_name, column_name, data_type FROM information_schema.columns "
            "WHERE table_schema = 'public' "
            "AND table_name IN ('users', 'sessions', 'refresh_tokens')"
        )
    )
    columns = {(row.table_name, row.column_name): row.data_type for row in result}
    for table in ("users", "sessions", "refresh_tokens"):
        assert columns[table, "id"] == "uuid"
    assert columns["refresh_tokens", "token_hash"] == "bytea"
    for (table, column), data_type in columns.items():
        if column.endswith("_at"):
            assert data_type == "timestamp with time zone", (table, column)
