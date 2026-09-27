from uuid import UUID, uuid4

from asyncpg import UniqueViolationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models import Secret
from app.repositories.secrets import SecretRepository
from app.schemas.secret import (
    SecretCreateRequest,
    SecretListQuery,
    SecretListResponse,
    SecretResponse,
    SecretSummary,
    SecretUpdateRequest,
)
from app.security.secrets import (
    EncryptedSecret,
    SecretDecryptionError,
    decrypt_secret_content,
    encrypt_secret_content,
)


class SecretNotFound(Exception):
    """Secret absent du périmètre de son propriétaire."""


class SecretUnavailable(Exception):
    """Secret du propriétaire indéchiffrable."""


class SecretStorageError(Exception):
    """Insertion du secret refusée sans détail de stockage public."""


def _is_nonce_collision(exc: IntegrityError) -> bool:
    cause = exc.orig.__cause__
    return (
        isinstance(cause, UniqueViolationError)
        and cause.constraint_name == "uq_secrets_key_version"
    )


async def create_secret(
    request: SecretCreateRequest, user_id: UUID, db: AsyncSession, settings: Settings
) -> SecretResponse:
    secret_id = uuid4()
    plaintext = request.content.get_secret_value()
    encrypted = encrypt_secret_content(plaintext, user_id, secret_id, settings)
    try:
        async with db.begin():
            row = await SecretRepository(db).add(
                Secret(
                    id=secret_id,
                    user_id=user_id,
                    title=request.title,
                    ciphertext=encrypted.ciphertext,
                    nonce=encrypted.nonce,
                    key_version=encrypted.key_version,
                    encryption_version=encrypted.encryption_version,
                )
            )
            response = SecretResponse(
                id=row.id,
                title=row.title,
                content=plaintext,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
    except IntegrityError as exc:
        if _is_nonce_collision(exc):
            raise SecretStorageError() from None
        raise
    return response


async def get_secret(
    secret_id: UUID, user_id: UUID, db: AsyncSession, settings: Settings
) -> SecretResponse:
    async with db.begin():
        row = await SecretRepository(db).get_owned_by_id(secret_id, user_id)
        if row is None:
            raise SecretNotFound()
        # Snapshot indépendant de l'expiration ORM après la transaction de lecture.
        encrypted = EncryptedSecret(
            row.ciphertext, row.nonce, row.key_version, row.encryption_version
        )
        title, created_at, updated_at = row.title, row.created_at, row.updated_at
    try:
        plaintext = decrypt_secret_content(encrypted, user_id, secret_id, settings)
    except SecretDecryptionError:
        raise SecretUnavailable() from None
    return SecretResponse(
        id=secret_id,
        title=title,
        content=plaintext,
        created_at=created_at,
        updated_at=updated_at,
    )


async def list_secrets(
    query: SecretListQuery, user_id: UUID, db: AsyncSession
) -> SecretListResponse:
    async with db.begin():
        rows = await SecretRepository(db).list_owned(
            user_id, query.limit, query.offset, query.q
        )
        response = SecretListResponse(
            items=[SecretSummary.model_validate(row) for row in rows[: query.limit]],
            limit=query.limit,
            offset=query.offset,
            has_more=len(rows) > query.limit,
        )
    return response


async def update_secret(
    secret_id: UUID,
    request: SecretUpdateRequest,
    user_id: UUID,
    db: AsyncSession,
    settings: Settings,
) -> SecretSummary:
    encrypted = None
    if request.content is not None:
        encrypted = encrypt_secret_content(
            request.content.get_secret_value(), user_id, secret_id, settings
        )
    try:
        async with db.begin():
            row = await SecretRepository(db).get_owned_by_id_for_update(
                secret_id, user_id
            )
            if row is None:
                raise SecretNotFound()
            if request.title is not None:
                row.title = request.title
            if encrypted is not None:
                row.ciphertext = encrypted.ciphertext
                row.nonce = encrypted.nonce
                row.key_version = encrypted.key_version
                row.encryption_version = encrypted.encryption_version
            await db.flush()
            await db.refresh(row, attribute_names=["updated_at"])
            response = SecretSummary.model_validate(row)
    except IntegrityError as exc:
        if _is_nonce_collision(exc):
            raise SecretStorageError() from None
        raise
    return response


async def delete_secret(secret_id: UUID, user_id: UUID, db: AsyncSession) -> None:
    async with db.begin():
        deleted = await SecretRepository(db).delete_owned_by_id(secret_id, user_id)
        if deleted is None:
            raise SecretNotFound()
