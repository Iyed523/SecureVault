from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.repositories.sessions import SessionRepository
from app.repositories.users import UserRepository
from app.schemas.user import PublicUser
from app.security.tokens import InvalidAccessToken, decode_access_token


class AuthenticationFailed(Exception):
    """Authentification refusée sans détail public."""


async def authenticate_user(
    token: str, session: AsyncSession, settings: Settings
) -> PublicUser:
    try:
        claims = decode_access_token(token, settings)
    except InvalidAccessToken:
        raise AuthenticationFailed() from None
    server_session = await SessionRepository(session).get_by_id_and_user_id(
        claims.session_id, claims.user_id
    )
    if (
        server_session is None
        or server_session.revoked_at is not None
        or server_session.expires_at <= datetime.now(UTC)
    ):
        raise AuthenticationFailed()
    user = await UserRepository(session).get_by_id(claims.user_id)
    if user is None or not user.is_active:
        raise AuthenticationFailed()
    return PublicUser.model_validate(user)
