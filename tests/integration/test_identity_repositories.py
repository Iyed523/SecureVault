from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session as ORMSession

from app.models import RefreshToken, Session, User
from app.repositories.refresh_tokens import RefreshTokenRepository
from app.repositories.sessions import SessionRepository
from app.repositories.users import UserRepository
from tests.integration.helpers import make_token_hash

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


async def test_repositories_read_without_commit(db_session: AsyncSession) -> None:
    def forbid_commit(session: ORMSession) -> None:
        pytest.fail("Un repository ne doit pas appeler commit()")

    event.listen(db_session.sync_session, "before_commit", forbid_commit)
    users = UserRepository(db_session)
    sessions = SessionRepository(db_session)
    tokens = RefreshTokenRepository(db_session)
    now = datetime.now(UTC)
    email = f"{uuid4()}@example.invalid"
    user = await users.add(User(email=email, password_hash="FAKE-PHC"))
    session = await sessions.add(
        Session(user_id=user.id, expires_at=now + timedelta(days=1))
    )
    token = await tokens.add(
        RefreshToken(
            session_id=session.id,
            token_hash=make_token_hash(),
            expires_at=now + timedelta(hours=1),
        )
    )
    user_id, session_id = user.id, session.id
    db_session.expunge_all()
    persisted_user = await users.get_by_id(user_id)
    assert persisted_user is not None and persisted_user.email == email
    by_email = await users.get_by_email(email)
    assert by_email is not None and by_email.id == user_id
    persisted_session = await sessions.get_by_id(session_id)
    assert persisted_session is not None and persisted_session.user_id == user_id
    persisted_token = await tokens.get_by_hash(token.token_hash)
    assert persisted_token is not None and persisted_token.session_id == session_id
    assert await users.get_by_id(uuid4()) is None
    assert await users.get_by_email("absent@example.invalid") is None
    assert await sessions.get_by_id(uuid4()) is None
    assert await tokens.get_by_hash(make_token_hash()) is None
    assert db_session.in_transaction()
    await db_session.rollback()
    assert await db_session.scalar(select(User).where(User.id == user_id)) is None
