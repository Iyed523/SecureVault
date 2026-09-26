from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Secret


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
