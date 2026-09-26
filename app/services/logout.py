from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.refresh_tokens import RefreshTokenRepository
from app.repositories.sessions import SessionRepository
from app.security.refresh_tokens import hash_refresh_token
from app.services.refresh import revoke_family


async def logout_session(raw: str, db: AsyncSession) -> None:
    try:
        digest = hash_refresh_token(raw)
    except UnicodeEncodeError:
        return
    async with db.begin():
        tokens = RefreshTokenRepository(db)
        session_id = await tokens.get_session_id_by_hash(digest)
        if session_id is None:
            return
        server_session = await SessionRepository(db).get_by_id_for_update(session_id)
        if server_session is not None:
            await revoke_family(server_session, tokens, datetime.now(UTC), "logout")
