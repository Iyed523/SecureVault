from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import get_current_user
from app.schemas.user import PublicUser

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=PublicUser)
async def me(user: Annotated[PublicUser, Depends(get_current_user)]) -> PublicUser:
    return user
