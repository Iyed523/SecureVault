from typing import Annotated, cast

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.session import get_session
from app.schemas.user import PublicUser
from app.services.authentication import AuthenticationFailed, authenticate_user

bearer = HTTPBearer(auto_error=False)


def get_settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> PublicUser:
    try:
        if credentials is None:
            raise AuthenticationFailed()
        return await authenticate_user(credentials.credentials, session, settings)
    except AuthenticationFailed:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


async def get_secret_session(
    current_user: Annotated[PublicUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AsyncSession:
    # get_current_user effectue uniquement des lectures. Libérer cette transaction
    # avant les use cases Secret, qui contrôlent leurs propres transactions.
    await session.rollback()
    return session
