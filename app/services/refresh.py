from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models import RefreshToken, Session
from app.repositories.refresh_tokens import RefreshTokenRepository
from app.repositories.sessions import SessionRepository
from app.repositories.users import UserRepository
from app.schemas.auth import TokenPairResponse
from app.security.refresh_tokens import generate_refresh_token, hash_refresh_token
from app.security.tokens import create_access_token


class InvalidRefreshToken(Exception):
    """Refresh token refusé sans distinction publique du motif."""


async def revoke_family(
    session: Session, tokens: RefreshTokenRepository, now: datetime, reason: str
) -> None:
    """Le verrou Session doit déjà être détenu avant toute mutation des tokens."""
    if session.revoked_at is None:
        session.revoked_at = now
        session.revocation_reason = reason
    await tokens.revoke_by_session(session.id, now)


async def _rotate(
    previous: RefreshToken,
    server_session: Session,
    db: AsyncSession,
    settings: Settings,
    now: datetime,
) -> TokenPairResponse:
    """Les verrous Session puis RefreshToken sont déjà détenus."""
    raw = generate_refresh_token()
    replacement = await RefreshTokenRepository(db).add(
        RefreshToken(
            session_id=server_session.id,
            token_hash=hash_refresh_token(raw),
            issued_at=now,
            expires_at=server_session.expires_at,
        )
    )
    previous.consumed_at = now
    previous.replaced_by_id = replacement.id
    await db.flush()
    return TokenPairResponse(
        access_token=create_access_token(
            server_session.user_id, server_session.id, settings
        ),
        refresh_token=raw,
        expires_in=settings.access_token_ttl_minutes * 60,
    )


async def refresh_tokens(
    raw: str, db: AsyncSession, settings: Settings
) -> TokenPairResponse:
    try:
        digest = hash_refresh_token(raw)
    except UnicodeEncodeError:
        raise InvalidRefreshToken() from None
    response = None
    async with db.begin():
        tokens = RefreshTokenRepository(db)
        session_id = await tokens.get_session_id_by_hash(digest)
        if session_id is None:
            raise InvalidRefreshToken()
        server_session = await SessionRepository(db).get_by_id_for_update(session_id)
        if server_session is None:
            raise InvalidRefreshToken()
        token = await tokens.get_by_hash_for_update(digest)
        if token is None or token.session_id != server_session.id:
            raise InvalidRefreshToken()
        now = datetime.now(UTC)
        if token.consumed_at is not None:
            await revoke_family(server_session, tokens, now, "refresh_token_reuse")
        elif (
            server_session.revoked_at is not None
            or server_session.expires_at <= now
            or token.revoked_at is not None
            or token.expires_at <= now
        ):
            raise InvalidRefreshToken()
        else:
            user = await UserRepository(db).get_by_id(
                server_session.user_id, populate_existing=True
            )
            if user is None or not user.is_active:
                await revoke_family(server_session, tokens, now, "user_inactive")
            else:
                response = await _rotate(token, server_session, db, settings, now)
    # Replay/inactivité : la révocation est commit avant l'erreur externe.
    if response is None:
        raise InvalidRefreshToken()
    return response
