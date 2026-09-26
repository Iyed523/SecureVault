from fastapi import APIRouter

from app.api.routes.auth import router as auth_router
from app.api.routes.health import router as health_router
from app.api.routes.ready import router as ready_router
from app.api.routes.secrets import router as secrets_router
from app.api.routes.users import router as users_router

router = APIRouter()
router.include_router(auth_router)
router.include_router(health_router)
router.include_router(ready_router)
router.include_router(users_router)
router.include_router(secrets_router)
