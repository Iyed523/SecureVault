from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user, get_secret_session, get_settings
from app.core.config import Settings
from app.schemas.secret import (
    SecretCreateRequest,
    SecretListQuery,
    SecretListResponse,
    SecretResponse,
    SecretSummary,
    SecretUpdateRequest,
)
from app.schemas.user import PublicUser
from app.services.secrets import (
    SecretNotFound,
    SecretStorageError,
    SecretUnavailable,
    create_secret,
    delete_secret,
    get_secret,
    list_secrets,
    update_secret,
)

router = APIRouter(prefix="/secrets", tags=["secrets"])


@router.get("", response_model=SecretListResponse)
async def collection(
    query: Annotated[SecretListQuery, Query()],
    current_user: Annotated[PublicUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_secret_session)],
) -> SecretListResponse:
    return await list_secrets(query, current_user.id, session)


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


@router.patch("/{secret_id}", response_model=SecretSummary)
async def update(
    secret_id: UUID,
    request: SecretUpdateRequest,
    current_user: Annotated[PublicUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_secret_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SecretSummary:
    try:
        return await update_secret(
            secret_id, request, current_user.id, session, settings
        )
    except SecretNotFound:
        raise HTTPException(status_code=404, detail="Secret not found.") from None
    except SecretStorageError:
        raise HTTPException(
            status_code=500, detail="Secret could not be stored."
        ) from None


@router.delete("/{secret_id}", status_code=204)
async def delete(
    secret_id: UUID,
    current_user: Annotated[PublicUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_secret_session)],
) -> Response:
    try:
        await delete_secret(secret_id, current_user.id, session)
    except SecretNotFound:
        raise HTTPException(status_code=404, detail="Secret not found.") from None
    return Response(status_code=204)
