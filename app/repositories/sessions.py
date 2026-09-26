from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Session


class SessionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, session: Session) -> Session:
        self.session.add(session)
        await self.session.flush()
        return session

    async def get_by_id(self, session_id: UUID) -> Session | None:
        return await self.session.get(Session, session_id)

    async def get_by_id_and_user_id(
        self, session_id: UUID, user_id: UUID
    ) -> Session | None:
        result = await self.session.execute(
            select(Session).where(Session.id == session_id, Session.user_id == user_id)
        )
        return result.scalar_one_or_none()
