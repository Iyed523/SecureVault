from datetime import timedelta
from secrets import token_bytes
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Secret, User
from tests.integration.test_identity_models import ISSUED, assert_rejected, make_user

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


def row(user_id: object, **changes: object) -> Secret:
    values = dict(
        user_id=user_id,
        title="public metadata",
        ciphertext=b"x" * 17,
        nonce=token_bytes(12),
        key_version=1,
        encryption_version=1,
    )
    values.update(changes)
    return Secret(**values)


async def test_secret_defaults_update_and_cascade(db_session: AsyncSession) -> None:
    user = await make_user(db_session)
    secret = row(user.id)
    db_session.add(secret)
    await db_session.flush()
    await db_session.refresh(secret)
    identifier = secret.id
    assert identifier.version == 4
    assert secret.title == "public metadata"
    assert isinstance(secret.ciphertext, bytes)
    assert len(secret.nonce) == 12
    assert secret.key_version == secret.encryption_version == 1
    assert (
        secret.created_at.utcoffset() == secret.updated_at.utcoffset() == timedelta(0)
    )
    assert "content" not in Secret.__table__.columns
    secret.updated_at = ISSUED
    await db_session.flush()
    secret.title = "changed metadata"
    await db_session.flush()
    await db_session.refresh(secret)
    assert secret.updated_at > ISSUED
    await db_session.execute(delete(User).where(User.id == user.id))
    assert (
        await db_session.scalar(select(Secret.id).where(Secret.id == identifier))
        is None
    )


@pytest.mark.parametrize(
    ("field", "value", "constraint"),
    [
        ("nonce", b"x" * 11, "ck_secrets_nonce_length"),
        ("nonce", b"x" * 13, "ck_secrets_nonce_length"),
        ("ciphertext", b"x" * 15, "ck_secrets_ciphertext_length"),
        ("key_version", 0, "ck_secrets_key_version_positive"),
        ("encryption_version", 0, "ck_secrets_encryption_version_positive"),
        ("user_id", uuid4(), "fk_secrets_user_id_users"),
        ("title", None, "title"),
        ("ciphertext", None, "ciphertext"),
        ("nonce", None, "nonce"),
        ("key_version", None, "key_version"),
        ("encryption_version", None, "encryption_version"),
        ("user_id", None, "user_id"),
    ],
)
async def test_secret_constraints(
    db_session: AsyncSession, field: str, value: object, constraint: str
) -> None:
    user = await make_user(db_session)
    values = {"user_id": user.id, field: value}
    await assert_rejected(db_session, row(**values), constraint)


async def test_nonce_unique_per_version_and_title_not_unique(
    db_session: AsyncSession,
) -> None:
    user = await make_user(db_session)
    other = await make_user(db_session)
    original = row(user.id)
    db_session.add(original)
    await db_session.flush()
    await assert_rejected(
        db_session, row(other.id, nonce=original.nonce), "uq_secrets_key_version"
    )
    db_session.add(row(user.id, nonce=original.nonce, key_version=2))
    db_session.add(row(user.id))
    await db_session.flush()
