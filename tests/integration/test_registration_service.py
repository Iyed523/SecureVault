from uuid import uuid4

import pytest
from asyncpg import NotNullViolationError, UniqueViolationError
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session as ORMSession

from app.models import RefreshToken, Session, User
from app.repositories.users import UserRepository
from app.schemas.auth import RegistrationRequest
from app.security.passwords import verify_password
from app.services.registration import EmailAlreadyRegistered, register_user

pytestmark = [pytest.mark.integration, pytest.mark.anyio]
PASSWORD = "Une phrase fictive de test 🔐"


async def test_registration_persists_canonical_user(db_session: AsyncSession) -> None:
    email = f"User-{uuid4()}@Example.COM"
    committed = []

    def on_commit(session: ORMSession) -> None:
        committed.append(True)

    event.listen(db_session.sync_session, "after_commit", on_commit)
    public = await register_user(
        RegistrationRequest(email=email, password=PASSWORD), db_session
    )
    assert committed == [True]
    assert not db_session.in_transaction()
    db_session.expunge_all()
    user = await db_session.get(User, public.id)
    assert user is not None
    assert user.email == public.email == email.casefold()
    assert user.is_active is public.is_active is True
    assert public.created_at == user.created_at
    assert PASSWORD not in user.password_hash
    assert user.password_hash.startswith("$argon2id$")
    assert verify_password(PASSWORD, user.password_hash)
    assert (
        await db_session.scalar(select(Session.id).where(Session.user_id == user.id))
        is None
    )
    assert (
        await db_session.scalar(
            select(RefreshToken.id).join(Session).where(Session.user_id == user.id)
        )
        is None
    )


@pytest.mark.parametrize("different_case", [False, True])
async def test_duplicate_uses_postgres_constraint_and_rolls_back(
    db_session: AsyncSession, different_case: bool
) -> None:
    email = f"user-{uuid4()}@example.com"
    request = RegistrationRequest(email=email, password=PASSWORD)
    original = await register_user(request, db_session)
    duplicate = RegistrationRequest(
        email=email.upper() if different_case else email, password=PASSWORD
    )
    with pytest.raises(EmailAlreadyRegistered) as caught:
        await register_user(duplicate, db_session)
    # Pas de pre-check : le doublon suit exactement le chemin d'une race d'INSERT.
    integrity = caught.value.__context__
    assert isinstance(integrity, IntegrityError)
    cause = integrity.orig.__cause__
    assert isinstance(cause, UniqueViolationError)
    assert cause.constraint_name == "uq_users_email"
    assert not db_session.in_transaction()
    user_ids = (
        await db_session.scalars(select(User.id).where(User.email == email))
    ).all()
    assert user_ids == [original.id]
    await db_session.rollback()
    # La session reste utilisable après le rollback de l'inscription échouée.
    other = await register_user(
        RegistrationRequest(email=f"{uuid4()}@example.com", password=PASSWORD),
        db_session,
    )
    assert other.id != original.id


async def test_error_after_flush_rolls_back_insert(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = RegistrationRequest(email=f"{uuid4()}@example.com", password=PASSWORD)
    original_add = UserRepository.add

    async def fail_after_insert(repository: UserRepository, user: User) -> User:
        await original_add(repository, user)
        raise RuntimeError("Échec contrôlé après INSERT réel")

    monkeypatch.setattr(UserRepository, "add", fail_after_insert)
    with pytest.raises(RuntimeError, match="Échec contrôlé"):
        await register_user(request, db_session)
    assert not db_session.in_transaction()
    assert (
        await db_session.scalar(select(User.id).where(User.email == request.email))
        is None
    )


async def test_other_integrity_error_is_not_a_duplicate(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_add = UserRepository.add

    async def invalidate_user(repository: UserRepository, user: User) -> User:
        user.password_hash = None
        return await original_add(repository, user)

    monkeypatch.setattr(UserRepository, "add", invalidate_user)
    request = RegistrationRequest(email=f"{uuid4()}@example.com", password=PASSWORD)
    with pytest.raises(IntegrityError) as caught:
        await register_user(request, db_session)
    assert isinstance(caught.value.orig.__cause__, NotNullViolationError)
    assert not db_session.in_transaction()
    assert (
        await db_session.scalar(select(User.id).where(User.email == request.email))
        is None
    )
