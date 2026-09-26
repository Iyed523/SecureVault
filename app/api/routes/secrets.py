from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user, get_secret_session, get_settings
from app.core.config import Settings
from app.schemas.secret import SecretCreateRequest, SecretResponse
from app.schemas.user import PublicUser
from app.services.secrets import (
    SecretNotFound,
    SecretStorageError,
    SecretUnavailable,
    create_secret,
    get_secret,
)

router = APIRouter(prefix="/secrets", tags=["secrets"])


@router.post("", response_model=SecretResponse, status_code=201)
async def create(
    request: SecretCreateRequest,
    current_user: Annotated[PublicUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_secret_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SecretResponse:
    try:
        return await create_secret(request, current_user.id, session, settings)
    except SecretStorageError:
        raise HTTPException(
            status_code=500, detail="Secret could not be stored."
        ) from None


@router.get("/{secret_id}", response_model=SecretResponse)
async def read(
    secret_id: UUID,
    current_user: Annotated[PublicUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_secret_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SecretResponse:
    try:
        return await get_secret(secret_id, current_user.id, session, settings)
    except SecretNotFound:
        raise HTTPException(status_code=404, detail="Secret not found.") from None
    except SecretUnavailable:
        raise HTTPException(
            status_code=500, detail="Secret content unavailable."
        ) from None
