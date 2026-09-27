from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import load_only

from app.models import Secret


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class SecretRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, secret: Secret) -> Secret:
        self.session.add(secret)
        await self.session.flush()
        return secret

    async def get_owned_by_id(self, secret_id: UUID, user_id: UUID) -> Secret | None:
        return await self.session.scalar(
            select(Secret).where(Secret.id == secret_id, Secret.user_id == user_id)
        )

    async def get_owned_by_id_for_update(
        self, secret_id: UUID, user_id: UUID
    ) -> Secret | None:
        return await self.session.scalar(
            select(Secret)
            .where(Secret.id == secret_id, Secret.user_id == user_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )

    async def list_owned(
        self, user_id: UUID, limit: int, offset: int, query: str | None = None
    ) -> Sequence[Secret]:
        statement = (
            select(Secret)
            .options(
                load_only(
                    Secret.id,
                    Secret.title,
                    Secret.created_at,
                    Secret.updated_at,
                    raiseload=True,
                )
            )
            .where(Secret.user_id == user_id)
        )
        if query is not None:
            statement = statement.where(
                Secret.title.ilike(f"%{escape_like(query)}%", escape="\\")
            )
        return (
            await self.session.scalars(
                statement.order_by(Secret.created_at.desc(), Secret.id.desc())
                .limit(limit + 1)
                .offset(offset)
            )
        ).all()

    async def delete_owned_by_id(self, secret_id: UUID, user_id: UUID) -> UUID | None:
        return await self.session.scalar(
            delete(Secret)
            .where(Secret.id == secret_id, Secret.user_id == user_id)
            .returning(Secret.id)
        )
