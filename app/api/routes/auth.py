from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_settings
from app.api.rate_limit import client_identifier, enforce_rate_limit, get_rate_limiter
from app.core.config import Settings
from app.db.session import get_session
from app.schemas.auth import (
    LoginRequest,
    RefreshTokenRequest,
    RegistrationRequest,
    TokenPairResponse,
)
from app.schemas.user import PublicUser
from app.security.rate_limit import RateLimiter
from app.services.login import InvalidCredentials, login_user
from app.services.logout import logout_session
from app.services.refresh import InvalidRefreshToken, refresh_tokens
from app.services.registration import EmailAlreadyRegistered, register_user

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register", response_model=PublicUser, status_code=status.HTTP_201_CREATED
)
async def register(
    request: RegistrationRequest,
    http_request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> PublicUser:
    await enforce_rate_limit(
        limiter,
        "register-ip",
        client_identifier(http_request),
        settings.register_rate_limit_per_ip,
        settings.rate_limit_window_seconds,
    )
    try:
        return await register_user(request, session)
    except EmailAlreadyRegistered:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Registration unavailable for this email.",
        ) from None


@router.post("/login", response_model=TokenPairResponse)
async def login(
    request: LoginRequest,
    http_request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> TokenPairResponse:
    await enforce_rate_limit(
        limiter,
        "login-ip",
        client_identifier(http_request),
        settings.login_rate_limit_per_ip,
        settings.rate_limit_window_seconds,
    )
    await enforce_rate_limit(
        limiter,
        "login-account",
        request.email,
        settings.login_rate_limit_per_account,
        settings.rate_limit_window_seconds,
    )
    try:
        return await login_user(request, session, settings)
    except InvalidCredentials:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


@router.post("/refresh", response_model=TokenPairResponse)
async def refresh(
    request: RefreshTokenRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenPairResponse:
    try:
        return await refresh_tokens(
            request.refresh_token.get_secret_value(), session, settings
        )
    except InvalidRefreshToken:
        raise HTTPException(status_code=401, detail="Invalid refresh token.") from None


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: RefreshTokenRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Response:
    await logout_session(request.refresh_token.get_secret_value(), session)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
