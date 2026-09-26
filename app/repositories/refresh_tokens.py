from datetime import datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import RefreshToken


class RefreshTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, token: RefreshToken) -> RefreshToken:
        self.session.add(token)
        await self.session.flush()
        return token

    async def get_by_hash(self, token_hash: bytes) -> RefreshToken | None:
        result = await self.session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        return result.scalar_one_or_none()

    async def get_session_id_by_hash(self, token_hash: bytes) -> UUID | None:
        return await self.session.scalar(
            select(RefreshToken.session_id).where(RefreshToken.token_hash == token_hash)
        )

    async def get_by_hash_for_update(self, token_hash: bytes) -> RefreshToken | None:
        return await self.session.scalar(
            select(RefreshToken)
            .where(RefreshToken.token_hash == token_hash)
            .with_for_update()
            .execution_options(populate_existing=True)
        )

    async def revoke_by_session(self, session_id: UUID, now: datetime) -> None:
        await self.session.execute(
            update(RefreshToken)
            .where(
                RefreshToken.session_id == session_id, RefreshToken.revoked_at.is_(None)
            )
            .values(revoked_at=now)
        )
