from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_settings
from app.core.config import Settings
from app.db.session import get_session
from app.schemas.auth import LoginRequest, RegistrationRequest, TokenResponse
from app.schemas.user import PublicUser
from app.services.login import InvalidCredentials, login_user
from app.services.registration import EmailAlreadyRegistered, register_user

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register", response_model=PublicUser, status_code=status.HTTP_201_CREATED
)
async def register(
    request: RegistrationRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> PublicUser:
    try:
        return await register_user(request, session)
    except EmailAlreadyRegistered:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Registration unavailable for this email.",
        ) from None


@router.post("/login", response_model=TokenResponse)
async def login(
    request: LoginRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenResponse:
    try:
        return await login_user(request, session, settings)
    except InvalidCredentials:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
