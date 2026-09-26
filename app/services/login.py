from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.core.config import Settings
from app.models import RefreshToken, Session
from app.repositories.refresh_tokens import RefreshTokenRepository
from app.repositories.sessions import SessionRepository
from app.repositories.users import UserRepository
from app.schemas.auth import LoginRequest, TokenPairResponse
from app.security.passwords import verify_password
from app.security.refresh_tokens import generate_refresh_token, hash_refresh_token
from app.security.tokens import create_access_token

# PHC public généré une fois ; le mot de passe aléatoire n'est pas conservé.
DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=1$9yP+hqSo+ABMWsKjhIX/fg$"
    "JFPRaIhFXmPy9lt8SBWZwyHNuhYVRDRzolmEKU99hZs"
)


class InvalidCredentials(Exception):
    """Credentials refusés sans distinction publique du motif."""


async def login_user(
    request: LoginRequest, session: AsyncSession, settings: Settings
) -> TokenPairResponse:
    async with session.begin():
        user = await UserRepository(session).get_by_email(request.email)
        user_id = user.id if user is not None else None
        password_hash = user.password_hash if user is not None else DUMMY_PASSWORD_HASH
        is_active = user.is_active if user is not None else False

    valid = await run_in_threadpool(
        verify_password, request.password.get_secret_value(), password_hash
    )
    if user_id is None or not valid or not is_active:
        raise InvalidCredentials()

    async with session.begin():
        user = await UserRepository(session).get_by_id(user_id, populate_existing=True)
        if user is None or not user.is_active or user.password_hash != password_hash:
            raise InvalidCredentials()
        now = datetime.now(UTC)
        server_session = await SessionRepository(session).add(
            Session(
                user_id=user.id,
                created_at=now,
                expires_at=now + timedelta(days=settings.session_ttl_days),
            )
        )
        raw_refresh = generate_refresh_token()
        await RefreshTokenRepository(session).add(
            RefreshToken(
                session_id=server_session.id,
                token_hash=hash_refresh_token(raw_refresh),
                issued_at=now,
                expires_at=server_session.expires_at,
            )
        )
        token = create_access_token(user.id, server_session.id, settings)
        response = TokenPairResponse(
            access_token=token,
            refresh_token=raw_refresh,
            expires_in=settings.access_token_ttl_minutes * 60,
        )
    return response
